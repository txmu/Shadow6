#include "../../Core-Cpp/src/json.hpp"
#include <sodium.h>
#include <fcntl.h>
#include <unistd.h>
#include <sys/stat.h>
#include <cerrno>
#include <cstring>

namespace {
struct File { int fd; ~File() { if (fd >= 0) close(fd); } };
struct Secret { unsigned char bytes[4097]{}; ~Secret() { sodium_memzero(bytes, sizeof bytes); } };
bool regular(const struct stat &s) {
    return S_ISREG(s.st_mode) && s.st_uid == geteuid() &&
        (s.st_mode & 07777) == 0600 && s.st_size > 0 && s.st_size <= 4096;
}
}

// The caller supplies a FileAuth-gated path. Never retain a Pony pointer.
// Packed result: role, listen/peer/application ports (big endian), seed, peer PK.
extern "C" int s6p_config(const char *path, unsigned char *out, size_t cap) noexcept {
    if (!path || !out || cap != 71) return -1;
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
        if (!JsonParser{}.parse(std::string_view(reinterpret_cast<char *>(secret.bytes), done), j) ||
            !schema(j, {{"role", Json::String}, {"listen_port", Json::Integer},
                       {"peer_port", Json::Integer}, {"application_port", Json::Integer},
                       {"private_key", Json::String}, {"peer_public_key", Json::String}})) return -1;
        auto role = j.at("role").text;
        if (role != "agent" && role != "client") return -1;
        unsigned char result[71]{};
        result[0] = role == "client" ? 1 : 0;
        size_t offset = 1;
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
        if (ok) memcpy(out, result, cap);
        sodium_memzero(result, sizeof result);
        return ok ? 0 : -1;
    } catch (...) { sodium_memzero(out, cap); return -1; }
}
