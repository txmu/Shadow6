#pragma once
#include "json.hpp"
#include <arpa/inet.h>
#include <array>
#include <cerrno>
#include <cstring>
#include <fcntl.h>
#include <memory>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <set>
#include <sys/stat.h>
#include <unistd.h>

namespace shadow6 {
template<class T, void (*Free)(T *)> using Owned = std::unique_ptr<T, decltype(Free)>;
using Key = Owned<EVP_PKEY, EVP_PKEY_free>;
inline std::string hex(const unsigned char *p, std::size_t n) {
  std::string out; out.reserve(n * 2);
  for (std::size_t i = 0; i < n; ++i) { out += "0123456789abcdef"[p[i] >> 4]; out += "0123456789abcdef"[p[i] & 15]; }
  return out;
}
inline bool unhex(std::string_view s, unsigned char *out, std::size_t n) {
  if (s.size() != n * 2) return false;
  for (std::size_t i = 0; i < n; ++i) {
    unsigned v{};
    auto r = std::from_chars(s.data() + 2 * i, s.data() + 2 * i + 2, v, 16);
    if (r.ec != std::errc{} || r.ptr != s.data() + 2 * i + 2) return false;
    out[i] = static_cast<unsigned char>(v);
  }
  return hex(out, n) == s; // One canonical representation for identities/tickets.
}
inline std::string public_hex(EVP_PKEY *key) {
  std::array<unsigned char, 32> data{}; std::size_t n = data.size();
  if (!key || EVP_PKEY_id(key) != EVP_PKEY_ED25519 || EVP_PKEY_get_raw_public_key(key, data.data(), &n) != 1 || n != data.size()) return {};
  return hex(data.data(), n);
}
inline Key private_key(std::string_view s) {
  std::array<unsigned char, 64> bytes{};
  if ((s.size() != 64 && s.size() != 128) || !unhex(s, bytes.data(), s.size() / 2)) return Key(nullptr, EVP_PKEY_free);
  Key key(EVP_PKEY_new_raw_private_key(EVP_PKEY_ED25519, nullptr, bytes.data(), 32), EVP_PKEY_free);
  bool valid = key && (s.size() == 64 || public_hex(key.get()) == hex(bytes.data() + 32, 32));
  OPENSSL_cleanse(bytes.data(), bytes.size());
  if (!valid) key.reset();
  return key;
}
inline bool valid_public(std::string_view s) {
  std::array<unsigned char, 32> key{}; return unhex(s, key.data(), key.size());
}
inline bool identity(std::string_view s) {
  if (s.empty() || s.size() > 64) return false;
  for (char c : s) if (!((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || (c >= '0' && c <= '9') || c == '-' || c == '_' || c == '.')) return false;
  return true;
}
struct Endpoint {
  sockaddr_storage address{};
  socklen_t size{};
  std::string host;
  unsigned port{};
  bool loopback{};
  std::string text() const { return (address.ss_family == AF_INET6 ? "[" + host + "]" : host) + ":" + std::to_string(port); }
};
inline bool endpoint(std::string_view s, Endpoint &out, bool allow_zero = false) {
  if (s.empty() || s.size() > 128 || !ascii(s)) return false;
  auto colon = s.rfind(':'); if (colon == std::string_view::npos) return false;
  std::string host(s.substr(0, colon));
  if (host.starts_with('[') && host.ends_with(']')) host = host.substr(1, host.size() - 2);
  unsigned port{}; auto r = std::from_chars(s.data() + colon + 1, s.data() + s.size(), port);
  if (r.ec != std::errc{} || r.ptr != s.data() + s.size() || port > 65535 || (!allow_zero && port == 0)) return false;
  out = Endpoint{}; out.port = port; out.host = host;
  auto *v4 = reinterpret_cast<sockaddr_in *>(&out.address);
  if (inet_pton(AF_INET, host.c_str(), &v4->sin_addr) == 1) {
    v4->sin_family = AF_INET; v4->sin_port = htons(static_cast<std::uint16_t>(port)); out.size = sizeof(*v4);
    out.loopback = (ntohl(v4->sin_addr.s_addr) >> 24) == 127;
    if ((ntohl(v4->sin_addr.s_addr) >> 28) >= 14) return false;
    return true;
  }
  auto *v6 = reinterpret_cast<sockaddr_in6 *>(&out.address);
  if (!s.starts_with('[') || inet_pton(AF_INET6, host.c_str(), &v6->sin6_addr) != 1 || IN6_IS_ADDR_MULTICAST(&v6->sin6_addr) || IN6_IS_ADDR_V4MAPPED(&v6->sin6_addr)) return false;
  v6->sin6_family = AF_INET6; v6->sin6_port = htons(static_cast<std::uint16_t>(port)); out.size = sizeof(*v6);
  out.loopback = IN6_IS_ADDR_LOOPBACK(&v6->sin6_addr); return true;
}

inline bool read_owned(const char *path, std::string &data) {
  const int fd = open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW | O_NONBLOCK);
  if (fd < 0) return false;
  struct stat st{};
  if (fstat(fd, &st) || !S_ISREG(st.st_mode) || (st.st_mode & 07777) != 0600 || st.st_uid != geteuid() || st.st_size < 1 || st.st_size > 1048576) { close(fd); return false; }
  data.clear(); std::array<char, 8192> chunk{};
  for (;;) {
    auto n = read(fd, chunk.data(), chunk.size());
    if (n < 0 && errno == EINTR) continue;
    if (n < 0 || data.size() + static_cast<std::size_t>(n) > 1048576) { close(fd); return false; }
    if (n == 0) break;
    data.append(chunk.data(), static_cast<std::size_t>(n));
  }
  struct stat after{};
  bool valid = fstat(fd, &after) == 0 && (after.st_mode & 07777) == 0600 && after.st_uid == geteuid() && static_cast<std::size_t>(after.st_size) == data.size();
  close(fd); return valid;
}
struct Peer { std::string key; std::set<std::string> allowed; };
struct Config {
  std::string role, id, secret, broker_key, agent_key, target_agent;
  Endpoint listen, broker, target;
  std::map<std::string, Peer> agents, clients;
};
inline bool peers(const Json &list, std::map<std::string, Peer> &out, bool clients) {
  if (list.kind != Json::Array || list.array.size() > 64) return false;
  for (const auto &j : list.array) {
    if (clients ? !schema(j, {{"id", Json::String}, {"pubkey", Json::String}, {"allowed_agents", Json::Array}})
                : !schema(j, {{"id", Json::String}, {"pubkey", Json::String}})) return false;
    auto id = j.at("id").text; auto key = j.at("pubkey").text;
    if (!identity(id) || !valid_public(key) || out.contains(id)) return false;
    Peer p; p.key = key;
    if (clients) {
      if (j.at("allowed_agents").array.size() > 64) return false;
      for (const auto &a : j.at("allowed_agents").array) if (a.kind != Json::String || !identity(a.text) || !p.allowed.insert(a.text).second) return false;
    }
    out.emplace(id, std::move(p));
  }
  return true;
}
inline bool parse_config(const Json &root, Config &c) {
  c = Config{};
  if (root.at("role").kind != Json::String) return false;
  c.role = root.at("role").text;
  if ((c.role != "broker" && c.role != "agent" && c.role != "client") || root.kind != Json::Object || root.object.size() != 2) return false;
  const auto &j = root.at(c.role);
  if (c.role == "broker") {
    if (!schema(j, {{"listen_addr", Json::String}, {"private_key", Json::String}, {"agents", Json::Array}, {"clients", Json::Array}}) || !peers(j.at("agents"), c.agents, false) || !peers(j.at("clients"), c.clients, true)) return false;
    std::set<std::string> keys;
    for (const auto &[id, p] : c.agents) if (c.clients.contains(id) || !keys.insert(p.key).second) return false;
    for (const auto &[id, p] : c.clients) {
      (void)id; if (!keys.insert(p.key).second) return false;
      for (const auto &a : p.allowed) if (!c.agents.contains(a)) return false;
    }
  } else {
    if (c.role == "agent") {
      if (!schema(j, {{"id", Json::String}, {"private_key", Json::String}, {"broker_addr", Json::String}, {"broker_pubkey", Json::String}, {"listen_addr", Json::String}, {"target_addr", Json::String}, {"client_pubkeys", Json::Object}, {"transport", Json::String}})) return false;
      if (!endpoint(j.at("target_addr").text, c.target) || !c.target.loopback || j.at("client_pubkeys").object.size() > 64) return false;
      std::set<std::string> keys;
      for (const auto &[id, key] : j.at("client_pubkeys").object) {
        if (!identity(id) || key.kind != Json::String || !valid_public(key.text) || !keys.insert(key.text).second) return false;
        c.clients.emplace(id, Peer{key.text, {}});
      }
    } else {
      if (!schema(j, {{"id", Json::String}, {"private_key", Json::String}, {"broker_addr", Json::String}, {"broker_pubkey", Json::String}, {"listen_addr", Json::String}, {"target_agent", Json::String}, {"agent_pubkey", Json::String}, {"transport", Json::String}})) return false;
      c.target_agent = j.at("target_agent").text; c.agent_key = j.at("agent_pubkey").text;
      if (!identity(c.target_agent) || !valid_public(c.agent_key)) return false;
    }
    c.id = j.at("id").text; c.broker_key = j.at("broker_pubkey").text;
    if (!identity(c.id) || !valid_public(c.broker_key) || !endpoint(j.at("broker_addr").text, c.broker) || j.at("transport").text != "sctp") return false;
  }
  c.secret = j.at("private_key").text;
  return private_key(c.secret) && endpoint(j.at("listen_addr").text, c.listen, true) && (c.role != "client" || c.listen.loopback);
}
inline bool load_config(const char *path, Config &c) {
  std::string data; Json j;
  return read_owned(path, data) && JsonParser{}.parse(data, j) && parse_config(j, c);
}
inline constexpr const char *features = R"({"core":"shadow6-cpp","version":"1.2.0","crosed_compiled":false,"crosed_max_level":0,"app_transport":false,"qubes_isolation":false,"gate_compiled":false,"gate_enabled_by_default":false,"utf8":true,"crosed_capabilities":[],"standalone":true,"control_protocol":"shadow6-cpp-wss-v1","data_transport":"sctp-tls13","max_sessions":16})";
} // namespace shadow6
