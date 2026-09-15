#include "../../Core-Cpp/src/json.hpp"
#include <sodium.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <arpa/inet.h>
#include <cerrno>
#include <cstring>

namespace {
struct File { int fd; ~File() { if (fd >= 0) close(fd); } };
struct Secret { unsigned char bytes[32769]{}; ~Secret() { sodium_memzero(bytes, sizeof bytes); } };
bool regular(const struct stat &s) {
    return S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
        (s.st_mode & 07777) == 0600 && s.st_size > 0 && s.st_size <= 32768;
}
bool ip_literal(const std::string &value, bool &loopback) {
    struct in_addr v4{};
    struct in6_addr v6{};
    loopback = false;
    if (inet_pton(AF_INET, value.c_str(), &v4) == 1) {
        loopback = (ntohl(v4.s_addr) >> 24) == 127;
        return !IN_MULTICAST(ntohl(v4.s_addr)) && v4.s_addr != INADDR_ANY;
    }
    if (inet_pton(AF_INET6, value.c_str(), &v6) == 1) {
        loopback = IN6_IS_ADDR_LOOPBACK(&v6);
        return !IN6_IS_ADDR_UNSPECIFIED(&v6) && !IN6_IS_ADDR_MULTICAST(&v6);
    }
    return false;
}
bool copy_host(unsigned char *out, size_t offset, const std::string &host) {
    if (host.empty() || host.size() > 255 || host.find('\0') != std::string::npos) return false;
    memcpy(out + offset, host.data(), host.size());
    return true;
}
}

// The caller supplies a FileAuth-gated path. Never retain a Pony pointer.
// Packed result: role, deployment flag, ports, seed, peer PK and three IP literals.
extern "C" int s6p_config(const char *path, unsigned char *out, size_t cap) noexcept {
    if (!path || !out || cap != 9034) return -1;
    memset(out, 0, cap);
    try {
        File file{open(path, O_RDONLY | O_NOFOLLOW | O_NONBLOCK | O_CLOEXEC)};
        struct stat before{}, after{};
        if (file.fd < 0 || fstat(file.fd, &before) || !regular(before)) return -1;
        Secret secret;
        size_t done = 0;
        while (done < sizeof secret.bytes) {
            ssize_t n = read(file.fd, secret.bytes + done, sizeof secret.bytes - done);
            if (n < 0 && errno == EINTR) continue;
            if (n < 0) return -1;
            if (!n) break;
            done += static_cast<size_t>(n);
        }
        if (fstat(file.fd, &after) || !regular(after) || before.st_dev != after.st_dev ||
            before.st_ino != after.st_ino || before.st_size != after.st_size ||
            before.st_mode != after.st_mode || before.st_uid != after.st_uid ||
            done != static_cast<size_t>(before.st_size)) return -1;
        using namespace shadow6;
        Json j;
        if (!JsonParser{}.parse(std::string_view(reinterpret_cast<char *>(secret.bytes), done), j)) return -1;
        Json pins;
        auto extra = j.object.find("peer_public_keys");
        if (extra != j.object.end()) {
            if (extra->second.kind != Json::Array || extra->second.array.size() > 255 ||
                j.at("role").text != "agent") return -1;
            pins = std::move(extra->second);
            j.object.erase(extra);
        }
        const bool legacy = schema(j, {{"role", Json::String}, {"listen_port", Json::Integer},
                       {"peer_port", Json::Integer}, {"application_port", Json::Integer},
                       {"private_key", Json::String}, {"peer_public_key", Json::String}});
        const bool extended = schema(j, {{"role", Json::String}, {"allow_external", Json::Boolean},
                       {"bind_host", Json::String}, {"peer_host", Json::String},
                       {"application_host", Json::String}, {"listen_port", Json::Integer},
                       {"peer_port", Json::Integer}, {"application_port", Json::Integer},
                       {"private_key", Json::String}, {"peer_public_key", Json::String}});
        if (!legacy && !extended) return -1;
        auto role = j.at("role").text;
        if (role != "agent" && role != "client" && role != "broker") return -1;
        unsigned char result[9034]{};
        result[0] = role == "client" ? 1 : (role == "broker" ? 2 : 0);
        const bool allow_external = extended && j.at("allow_external").integer == 1;
        result[1] = allow_external ? 1 : 0;
        size_t offset = 2;
        for (auto name : {"listen_port", "peer_port", "application_port"}) {
            auto n = j.at(name).integer;
            if (n < 1024 || n > 65535) return -1;
            result[offset++] = static_cast<unsigned char>(n >> 8);
            result[offset++] = static_cast<unsigned char>(n);
        }
        if (j.at("listen_port").integer == j.at("peer_port").integer ||
            j.at("listen_port").integer == j.at("application_port").integer ||
            j.at("peer_port").integer == j.at("application_port").integer) return -1;
        bool ok = true;
        for (auto name : {"private_key", "peer_public_key"}) {
            auto &text = j.object.at(name).text;
            ok = ok && text.size() == 64 &&
                sodium_hex2bin(result + offset, 32, text.data(), text.size(), nullptr, nullptr, nullptr) == 0;
            sodium_memzero(text.data(), text.size());
            offset += 32;
        }
        size_t count = 1;
        memcpy(result + 842, result + 40, 32);
        for (const auto &pin : pins.array) {
            if (pin.kind != Json::String || pin.text.size() != 64 ||
                sodium_hex2bin(result + 842 + count * 32, 32, pin.text.data(),
                    pin.text.size(), nullptr, nullptr, nullptr) != 0) { ok = false; break; }
            for (size_t previous = 0; previous < count; ++previous)
                if (sodium_memcmp(result + 842 + previous * 32, result + 842 + count * 32, 32) == 0)
                    ok = false;
            ++count;
        }
        result[840] = static_cast<unsigned char>(count >> 8);
        result[841] = static_cast<unsigned char>(count);
        const std::string loopback = "127.0.0.1";
        const auto &bind = extended ? j.at("bind_host").text : loopback;
        const auto &peer = extended ? j.at("peer_host").text : loopback;
        const auto &application = extended ? j.at("application_host").text : loopback;
        bool bind_loopback{}, peer_loopback{}, application_loopback{};
        ok = ok && ip_literal(bind, bind_loopback) && ip_literal(peer, peer_loopback) &&
            ip_literal(application, application_loopback);
        if (extended && !allow_external &&
            (!bind_loopback || !peer_loopback || !application_loopback)) ok = false;
        ok = ok && copy_host(result, 72, bind) && copy_host(result, 328, peer) &&
            copy_host(result, 584, application);
        if (ok) memcpy(out, result, cap);
        sodium_memzero(result, sizeof result);
        return ok ? 0 : -1;
    } catch (...) { sodium_memzero(out, cap); return -1; }
}
