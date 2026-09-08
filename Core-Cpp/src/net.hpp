#pragma once
#include "config.hpp"
#include <chrono>
#include <csignal>
#include <openssl/ssl.h>
#include <poll.h>
#include <sys/socket.h>

namespace shadow6 {
inline volatile std::sig_atomic_t stopped = 0;
using Clock = std::chrono::steady_clock;
using Deadline = Clock::time_point;
inline Deadline deadline(unsigned seconds = 5) { return Clock::now() + std::chrono::seconds(seconds); }
inline bool wait_fd(int fd, short events, Deadline until) {
  while (!stopped && Clock::now() < until) {
    pollfd p{fd, events, 0};
    int n = poll(&p, 1, 100);
    if (n < 0 && errno != EINTR) return false;
    if (n > 0) return (p.revents & (events | POLLHUP | POLLERR)) != 0;
  }
  return false;
}
struct Fd {
  int value{-1};
  explicit Fd(int v = -1) : value(v) {}
  Fd(const Fd &) = delete;
  Fd &operator=(const Fd &) = delete;
  Fd(Fd &&v) noexcept : value(v.value) { v.value = -1; }
  ~Fd() { if (value >= 0) close(value); }
  explicit operator bool() const { return value >= 0; }
};
inline bool nonblocking(int fd) { int f = fcntl(fd, F_GETFL); return f >= 0 && fcntl(fd, F_SETFL, f | O_NONBLOCK) == 0 && fcntl(fd, F_SETFD, FD_CLOEXEC) == 0; }
inline Fd listen_socket(const Endpoint &ep, int protocol) {
  Fd fd(socket(ep.address.ss_family, SOCK_STREAM, protocol));
  if (!fd || !nonblocking(fd.value)) return Fd{};
  int one = 1;
  if (setsockopt(fd.value, SOL_SOCKET, SO_REUSEADDR, &one, sizeof(one)) != 0 ||
      bind(fd.value, reinterpret_cast<const sockaddr *>(&ep.address), ep.size) || listen(fd.value, 16)) return Fd{};
  return fd;
}
inline Fd connect_socket(const Endpoint &ep, int protocol) {
  Fd fd(socket(ep.address.ss_family, SOCK_STREAM, protocol));
  if (!fd || !nonblocking(fd.value)) return Fd{};
  if (connect(fd.value, reinterpret_cast<const sockaddr *>(&ep.address), ep.size) != 0) {
    if (errno != EINPROGRESS || !wait_fd(fd.value, POLLOUT, deadline())) return Fd{};
    int error{}; socklen_t n = sizeof(error);
    if (getsockopt(fd.value, SOL_SOCKET, SO_ERROR, &error, &n) || error) return Fd{};
  }
  return fd;
}
inline Endpoint socket_endpoint(int fd, bool peer = false) {
  Endpoint ep; ep.size = sizeof(ep.address);
  if ((peer ? getpeername(fd, reinterpret_cast<sockaddr *>(&ep.address), &ep.size)
            : getsockname(fd, reinterpret_cast<sockaddr *>(&ep.address), &ep.size)) != 0) return ep;
  std::array<char, INET6_ADDRSTRLEN> host{};
  if (ep.address.ss_family == AF_INET) {
    auto *a = reinterpret_cast<sockaddr_in *>(&ep.address); ep.port = ntohs(a->sin_port);
    if (!inet_ntop(AF_INET, &a->sin_addr, host.data(), host.size())) return Endpoint{};
  } else {
    auto *a = reinterpret_cast<sockaddr_in6 *>(&ep.address); ep.port = ntohs(a->sin6_port);
    if (!inet_ntop(AF_INET6, &a->sin6_addr, host.data(), host.size())) return Endpoint{};
  }
  ep.host = host.data(); return ep;
}
inline std::string sign(EVP_PKEY *key, std::string_view data) {
  Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  std::array<unsigned char, 64> sig{}; std::size_t n = sig.size();
  if (!ctx || EVP_DigestSignInit(ctx.get(), nullptr, nullptr, nullptr, key) != 1 || EVP_DigestSign(ctx.get(), sig.data(), &n, reinterpret_cast<const unsigned char *>(data.data()), data.size()) != 1 || n != sig.size()) return {};
  return hex(sig.data(), n);
}
inline bool verify(std::string_view pub, std::string_view data, std::string_view signature) {
  std::array<unsigned char, 32> raw{}; std::array<unsigned char, 64> sig{};
  if (!unhex(pub, raw.data(), raw.size()) || !unhex(signature, sig.data(), sig.size())) return false;
  Key key(EVP_PKEY_new_raw_public_key(EVP_PKEY_ED25519, nullptr, raw.data(), raw.size()), EVP_PKEY_free);
  Owned<EVP_MD_CTX, EVP_MD_CTX_free> ctx(EVP_MD_CTX_new(), EVP_MD_CTX_free);
  return key && ctx && EVP_DigestVerifyInit(ctx.get(), nullptr, nullptr, nullptr, key.get()) == 1 && EVP_DigestVerify(ctx.get(), sig.data(), sig.size(), reinterpret_cast<const unsigned char *>(data.data()), data.size()) == 1;
}

class TlsContext {
  std::set<std::string> pins_;
  Owned<SSL_CTX, SSL_CTX_free> ctx_{nullptr, SSL_CTX_free};
  static int verify_pinned(X509_STORE_CTX *store, void *argument) {
    auto *self = static_cast<TlsContext *>(argument);
    auto *cert = X509_STORE_CTX_get0_cert(store);
    Key key(cert ? X509_get_pubkey(cert) : nullptr, EVP_PKEY_free);
    // Explicit raw-Ed25519 trust model: validate the pinned identity, certificate
    // signature and validity. A PKI error is never accepted unconditionally.
    bool valid = cert && key && self->pins_.contains(public_hex(key.get())) &&
      X509_get_signature_nid(cert) == NID_ED25519 && X509_verify(cert, key.get()) == 1 &&
      X509_cmp_current_time(X509_get0_notBefore(cert)) < 0 && X509_cmp_current_time(X509_get0_notAfter(cert)) > 0;
    X509_STORE_CTX_set_error(store, valid ? X509_V_OK : X509_V_ERR_CERT_REJECTED);
    return valid ? 1 : 0;
  }
public:
  TlsContext(const std::string &secret, std::set<std::string> pins) : pins_(std::move(pins)) {
    auto key = private_key(secret);
    Owned<X509, X509_free> cert(X509_new(), X509_free);
    ctx_.reset(SSL_CTX_new(TLS_method()));
    if (!key || !cert || !ctx_) { ctx_.reset(); return; }
    auto *name = X509_get_subject_name(cert.get());
    bool ok = X509_set_version(cert.get(), 2) == 1 && ASN1_INTEGER_set(X509_get_serialNumber(cert.get()), 1) == 1 &&
      X509_gmtime_adj(X509_getm_notBefore(cert.get()), -60) && X509_gmtime_adj(X509_getm_notAfter(cert.get()), 31536000) &&
      X509_set_pubkey(cert.get(), key.get()) == 1 &&
      X509_NAME_add_entry_by_txt(name, "CN", MBSTRING_ASC, reinterpret_cast<const unsigned char *>("shadow6-cpp"), -1, -1, 0) == 1 &&
      X509_set_issuer_name(cert.get(), name) == 1 && X509_sign(cert.get(), key.get(), nullptr) > 0 &&
      SSL_CTX_set_min_proto_version(ctx_.get(), TLS1_3_VERSION) == 1 && SSL_CTX_set_max_proto_version(ctx_.get(), TLS1_3_VERSION) == 1 &&
      SSL_CTX_use_certificate(ctx_.get(), cert.get()) == 1 && SSL_CTX_use_PrivateKey(ctx_.get(), key.get()) == 1 && SSL_CTX_check_private_key(ctx_.get()) == 1;
    if (!ok) { ctx_.reset(); return; }
    SSL_CTX_set_verify(ctx_.get(), SSL_VERIFY_PEER | SSL_VERIFY_FAIL_IF_NO_PEER_CERT, nullptr);
    SSL_CTX_set_cert_verify_callback(ctx_.get(), verify_pinned, this);
    SSL_CTX_set_options(ctx_.get(), SSL_OP_NO_TICKET | SSL_OP_NO_RENEGOTIATION);
    SSL_CTX_set_session_cache_mode(ctx_.get(), SSL_SESS_CACHE_OFF);
    SSL_CTX_set_num_tickets(ctx_.get(), 0);
    SSL_CTX_set_max_early_data(ctx_.get(), 0);
  }
  SSL_CTX *get() const { return ctx_.get(); }
};

class Channel {
  Owned<SSL, SSL_free> ssl_{nullptr, SSL_free};
  bool again(int result, Deadline until) {
    auto error = SSL_get_error(ssl_.get(), result);
    return (error == SSL_ERROR_WANT_READ || error == SSL_ERROR_WANT_WRITE) && wait_fd(fd(), error == SSL_ERROR_WANT_READ ? POLLIN : POLLOUT, until);
  }
public:
  Channel(TlsContext &ctx, int fd) {
    if (ctx.get()) ssl_.reset(SSL_new(ctx.get()));
    if (ssl_ && SSL_set_fd(ssl_.get(), fd) != 1) ssl_.reset();
  }
  bool handshake(bool server) {
    if (!ssl_) return false;
    auto until = deadline();
    do { int n = server ? SSL_accept(ssl_.get()) : SSL_connect(ssl_.get()); if (n == 1) return SSL_get_verify_result(ssl_.get()) == X509_V_OK; if (!again(n, until)) return false; } while (!stopped);
    return false;
  }
  int fd() const { return SSL_get_fd(ssl_.get()); }
  bool pending() const { return SSL_pending(ssl_.get()) > 0; }
  std::string peer_key() const {
    Owned<X509, X509_free> cert(SSL_get1_peer_certificate(ssl_.get()), X509_free);
    Key key(cert ? X509_get_pubkey(cert.get()) : nullptr, EVP_PKEY_free); return public_hex(key.get());
  }
  bool read(void *data, std::size_t length, Deadline until) {
    auto *p = static_cast<unsigned char *>(data);
    while (length && !stopped && Clock::now() < until) {
      std::size_t n{}; int result = SSL_read_ex(ssl_.get(), p, length, &n);
      if (result != 1) { if (!again(result, until)) return false; continue; }
      p += n; length -= n;
    }
    return length == 0;
  }
  bool write(std::string_view data) {
    auto until = deadline();
    while (!data.empty() && !stopped && Clock::now() < until) {
      std::size_t n{}; int result = SSL_write_ex(ssl_.get(), data.data(), data.size(), &n);
      if (result != 1) { if (!again(result, until)) return false; continue; }
      data.remove_prefix(n);
    }
    return data.empty();
  }
  bool frame(std::string_view data) {
    if (data.empty() || data.size() > 16384) return false;
    std::string wire(4, '\0'); auto n = static_cast<std::uint32_t>(data.size());
    for (unsigned i = 0; i < 4; ++i) wire[i] = static_cast<char>(n >> (24 - 8 * i));
    wire += data; return write(wire);
  }
  bool frame(std::string &data, Deadline until) {
    std::array<unsigned char, 4> header{};
    if (!read(header.data(), header.size(), until)) return false;
    std::size_t n = 0; for (auto c : header) n = (n << 8) | c;
    if (n == 0 || n > 16384) return false;
    data.resize(n); return read(data.data(), n, until);
  }
};

inline std::string base64(const unsigned char *p, int n) {
  std::string out(static_cast<std::size_t>(4 * ((n + 2) / 3) + 1), '\0');
  int length = EVP_EncodeBlock(reinterpret_cast<unsigned char *>(out.data()), p, n);
  out.resize(static_cast<std::size_t>(length)); return out;
}
inline std::string ws_accept(std::string key) {
  key += "258EAFA5-E914-47DA-95CA-C5AB0DC85B11";
  std::array<unsigned char, EVP_MAX_MD_SIZE> digest{}; unsigned n{};
  if (EVP_Digest(key.data(), key.size(), digest.data(), &n, EVP_sha1(), nullptr) != 1) return {};
  return base64(digest.data(), static_cast<int>(n));
}
inline std::string lower(std::string s) { for (auto &c : s) if (c >= 'A' && c <= 'Z') c = static_cast<char>(c + ('a' - 'A')); return s; }
class WebSocket {
  Channel &channel_;
  bool server_;
public:
  WebSocket(Channel &channel, bool server) : channel_(channel), server_(server) {}
  bool upgrade(std::string_view host = "localhost") {
    std::array<unsigned char, 16> nonce{};
    if (RAND_bytes(nonce.data(), nonce.size()) != 1) return false;
    std::string key = base64(nonce.data(), nonce.size());
    if (!server_ && !channel_.write("GET /shadow6-cpp/v1 HTTP/1.1\r\nHost: " + std::string(host) + "\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Version: 13\r\nSec-WebSocket-Key: " + key + "\r\n\r\n")) return false;
    std::string header; auto until = deadline(); char c{};
    while (header.size() < 4096 && !header.ends_with("\r\n\r\n")) { if (!channel_.read(&c, 1, until)) return false; header += c; }
    if (!header.ends_with("\r\n\r\n") || !ascii(header.substr(0, header.find("\r\n")))) return false;
    auto end = header.find("\r\n");
    if (header.substr(0, end) != (server_ ? "GET /shadow6-cpp/v1 HTTP/1.1" : "HTTP/1.1 101 Switching Protocols")) return false;
    std::map<std::string, std::string> fields;
    for (auto start = end + 2; start < header.size() - 2; start = end + 2) {
      end = header.find("\r\n", start); auto line = header.substr(start, end - start); auto colon = line.find(':');
      if (colon == std::string::npos || colon == 0 || !ascii(line)) return false;
      auto name = lower(line.substr(0, colon)); auto value = line.substr(colon + 1);
      while (value.starts_with(' ')) value.erase(0, 1);
      if (!fields.emplace(name, value).second) return false;
    }
    if (lower(fields["upgrade"]) != "websocket" || lower(fields["connection"]) != "upgrade" || fields.contains("origin") || fields.contains("sec-websocket-extensions")) return false;
    if (!server_) return fields["sec-websocket-accept"] == ws_accept(key);
    key = fields["sec-websocket-key"];
    std::array<unsigned char, 32> decoded{};
    if (fields["sec-websocket-version"] != "13" || key.size() != 24 || !key.ends_with("==") || EVP_DecodeBlock(decoded.data(), reinterpret_cast<const unsigned char *>(key.data()), 24) != 18 || base64(decoded.data(), 16) != key) return false;
    return channel_.write("HTTP/1.1 101 Switching Protocols\r\nUpgrade: websocket\r\nConnection: Upgrade\r\nSec-WebSocket-Accept: " + ws_accept(key) + "\r\n\r\n");
  }
  bool send(const Json &j) {
    auto data = encode(j); if (data.size() > 16384) return false;
    std::string wire(1, static_cast<char>(0x81)); unsigned mask = server_ ? 0U : 128U;
    if (data.size() < 126) wire += static_cast<char>(mask | data.size());
    else { wire += static_cast<char>(mask | 126U); wire += static_cast<char>(data.size() >> 8); wire += static_cast<char>(data.size()); }
    if (!server_) {
      std::array<unsigned char, 4> key{}; if (RAND_bytes(key.data(), key.size()) != 1) return false;
      wire.append(reinterpret_cast<const char *>(key.data()), key.size());
      for (std::size_t i = 0; i < data.size(); ++i) data[i] = static_cast<char>(static_cast<unsigned char>(data[i]) ^ key[i % 4]);
    }
    return channel_.write(wire + data);
  }
  bool receive(Json &j, unsigned timeout = 15) {
    auto until = deadline(timeout); std::array<unsigned char, 2> head{};
    if (!channel_.read(head.data(), head.size(), until) || head[0] != 0x81 || ((head[1] & 128U) != 0) != server_) return false;
    std::size_t n = head[1] & 127U;
    if (n == 127) return false;
    if (n == 126) { if (!channel_.read(head.data(), head.size(), until)) return false; n = (head[0] << 8) | head[1]; if (n < 126) return false; }
    if (n == 0 || n > 16384) return false;
    std::array<unsigned char, 4> key{};
    if (server_ && !channel_.read(key.data(), key.size(), until)) return false;
    std::string data(n, '\0'); if (!channel_.read(data.data(), n, until)) return false;
    if (server_) for (std::size_t i = 0; i < n; ++i) data[i] = static_cast<char>(static_cast<unsigned char>(data[i]) ^ key[i % 4]);
    return JsonParser{}.parse(data, j) && j.at("version").kind == Json::Integer && j.at("version").integer == 1;
  }
};
} // namespace shadow6
