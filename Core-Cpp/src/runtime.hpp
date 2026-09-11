#pragma once
#include "net.hpp"
#include <atomic>
#include <functional>
#include <mutex>
#include <thread>

namespace shadow6 {
inline std::int64_t epoch() { return static_cast<std::int64_t>(std::time(nullptr)); }
inline std::string ticket_payload(const Json &j) { return "shadow6-cpp-ticket-v1\n" + encode(j); }
inline bool plain_write(int fd, std::string_view data) {
  auto until = deadline();
  while (!data.empty() && !stopped && Clock::now() < until) {
    auto n = send(fd, data.data(), data.size(), MSG_NOSIGNAL);
    if (n > 0) data.remove_prefix(static_cast<std::size_t>(n));
    else if (n < 0 && (errno == EAGAIN || errno == EWOULDBLOCK || errno == EINTR)) { if (!wait_fd(fd, POLLOUT, until)) return false; }
    else return false;
  }
  return data.empty();
}
// One ordered SCTP association (stream zero) per tunnel. Explicit FIN records
// preserve TCP half-close without closing the opposite direction prematurely.
inline bool tunnel(Channel &encrypted, int local) {
  bool local_fin = false, remote_fin = false;
  auto end = deadline(3600), idle = deadline(60);
  std::array<char, 8192> data{};
  while (!stopped && Clock::now() < end && Clock::now() < idle) {
    if (local_fin && remote_fin) return true;
    std::array<pollfd, 2> fds{{{local, static_cast<short>(local_fin ? 0 : POLLIN), 0}, {encrypted.fd(), static_cast<short>(remote_fin ? 0 : POLLIN), 0}}};
    if (local_fin) fds[0].fd = -1;
    if (remote_fin) fds[1].fd = -1;
    int n = poll(fds.data(), fds.size(), encrypted.pending() ? 0 : 100);
    if (n < 0 && errno != EINTR) return false;
    if (!local_fin && fds[0].revents) {
      auto count = recv(local, data.data(), data.size(), 0);
      if (count == 0) { if (!encrypted.frame(std::string_view("\2", 1))) return false; local_fin = true; }
      else if (count > 0) {
        std::string frame(1, '\1'); frame.append(data.data(), static_cast<std::size_t>(count));
        if (!encrypted.frame(frame)) return false;
      } else if (errno != EAGAIN && errno != EWOULDBLOCK && errno != EINTR) return false;
      idle = deadline(60);
    }
    if (!remote_fin && (fds[1].revents || encrypted.pending())) {
      std::string frame;
      if (!encrypted.frame(frame, deadline())) return false;
      if (frame[0] == '\2' && frame.size() == 1) { remote_fin = true; shutdown(local, SHUT_WR); }
      else if (frame[0] == '\1' && frame.size() > 1 && frame.size() <= 8193) {
        if (!plain_write(local, std::string_view(frame).substr(1))) return false;
      } else return false;
      idle = deadline(60);
    }
  }
  return false;
}
inline void ready(const char *role, const Endpoint &ep) {
  auto j = message("ready"); j.object["role"] = Json(role); j.object["listen_addr"] = Json(ep.text());
  std::puts(encode(j).c_str()); std::fflush(stdout);
}
inline void serve(int listener, const std::function<void(int)> &handler) {
  struct Worker { std::thread thread; std::atomic<bool> done{true}; };
  std::array<Worker, 16> workers;
  auto refill = deadline(1); unsigned tokens = 16;
  while (!stopped) {
    if (Clock::now() >= refill) { refill = deadline(1); tokens = 16; }
    if (!tokens) { std::this_thread::sleep_for(std::chrono::milliseconds(50)); continue; }
    if (!wait_fd(listener, POLLIN, deadline(1))) continue;
    Fd accepted(accept(listener, nullptr, nullptr));
    if (!accepted || !nonblocking(accepted.value)) continue;
    --tokens;
    for (auto &worker : workers) {
      if (!worker.done.load()) continue;
      if (worker.thread.joinable()) worker.thread.join();
      worker.done = false; int fd = accepted.value; accepted.value = -1;
      worker.thread = std::thread([&handler, &worker, fd] {
        Fd owned(fd); handler(fd); worker.done = true;
      });
      break;
    }
  }
  for (auto &worker : workers) if (worker.thread.joinable()) worker.thread.join();
}

class Broker {
  const Config &cfg_;
  std::mutex mutex_;
  std::map<std::string, Endpoint> registered_;
  Key signer_;
public:
  explicit Broker(const Config &cfg) : cfg_(cfg), signer_(private_key(cfg.secret)) {}
  bool grant(const std::string &client_id, const std::string &agent_id, Json &result) {
    auto client = cfg_.clients.find(client_id); auto agent = cfg_.agents.find(agent_id);
    if (client == cfg_.clients.end() || agent == cfg_.agents.end() || !client->second.allowed.contains(agent_id)) return false;
    Endpoint address;
    { std::lock_guard lock(mutex_); auto i = registered_.find(agent_id); if (i == registered_.end()) return false; address = i->second; }
    std::array<unsigned char, 32> nonce{}; if (RAND_bytes(nonce.data(), nonce.size()) != 1) return false;
    Json ticket = Json::obj();
    ticket.object["version"] = Json(std::int64_t{1});
    ticket.object["client"] = Json(client_id); ticket.object["client_key"] = Json(client->second.key);
    ticket.object["agent"] = Json(agent_id); ticket.object["agent_key"] = Json(agent->second.key);
    ticket.object["issued_at"] = Json(epoch()); ticket.object["expires_at"] = Json(ticket.at("issued_at").integer + 30);
    ticket.object["nonce"] = Json(hex(nonce.data(), nonce.size()));
    auto signature = sign(signer_.get(), ticket_payload(ticket)); if (signature.empty()) return false;
    result = message("grant"); result.object["endpoint"] = Json(address.text());
    result.object["ticket"] = std::move(ticket); result.object["signature"] = Json(signature);
    return true;
  }
  void handle(TlsContext &tls, int fd) {
    Channel channel(tls, fd); if (!channel.handshake(true)) return;
    const auto pub = channel.peer_key(); std::string id; bool agent = false;
    for (const auto &[name, p] : cfg_.agents) if (p.key == pub) { id = name; agent = true; }
    for (const auto &[name, p] : cfg_.clients) if (p.key == pub) id = name;
    if (id.empty()) return;
    WebSocket ws(channel, true); if (!ws.upgrade()) return;
    if (agent) {
      Json j;
      if (!ws.receive(j, 5) || !schema(j, {{"version", Json::Integer}, {"type", Json::String}, {"port", Json::Integer}}) || j.at("type").text != "register" || j.at("port").integer < 1 || j.at("port").integer > 65535) return;
      auto ep = socket_endpoint(fd, true); ep.port = static_cast<unsigned>(j.at("port").integer);
      { std::lock_guard lock(mutex_); if (!registered_.emplace(id, ep).second) return; }
      if (ws.send(message("registered"))) {
        while (!stopped && ws.receive(j)) {
          if (!schema(j, {{"version", Json::Integer}, {"type", Json::String}}) || j.at("type").text != "ping" || !ws.send(message("pong"))) break;
        }
      }
      { std::lock_guard lock(mutex_); registered_.erase(id); }
    } else {
      for (unsigned count = 0; count < 128 && !stopped; ++count) {
        Json j; if (!ws.receive(j, 5)) return;
        if (schema(j, {{"version", Json::Integer}, {"type", Json::String}}) && j.at("type").text == "features") {
          Json report; if (!JsonParser{}.parse(features, report) || !ws.send(report)) return;
        } else {
          if (!schema(j, {{"version", Json::Integer}, {"type", Json::String}, {"agent", Json::String}}) || j.at("type").text != "open") return;
          Json reply;
          if (!grant(id, j.at("agent").text, reply)) reply = message("denied");
          if (!ws.send(reply)) return;
        }
      }
    }
  }
};

class Tickets {
  std::mutex mutex_;
  std::map<std::string, std::int64_t> seen_;
public:
  bool accept(const Config &cfg, const std::string &peer_key, const Json &envelope) {
    if (!schema(envelope, {{"version", Json::Integer}, {"ticket", Json::Object}, {"signature", Json::String}}) || envelope.at("version").integer != 1) return false;
    const auto &j = envelope.at("ticket");
    if (!schema(j, {{"version", Json::Integer}, {"client", Json::String}, {"client_key", Json::String}, {"agent", Json::String}, {"agent_key", Json::String}, {"issued_at", Json::Integer}, {"expires_at", Json::Integer}, {"nonce", Json::String}})) return false;
    auto client = cfg.clients.find(j.at("client").text); auto now = epoch();
    std::array<unsigned char, 32> nonce{};
    if (j.at("version").integer != 1 || j.at("agent").text != cfg.id || j.at("agent_key").text != public_hex(private_key(cfg.secret).get()) ||
        client == cfg.clients.end() || client->second.key != peer_key || j.at("client_key").text != peer_key ||
        j.at("issued_at").integer > now + 5 || j.at("expires_at").integer <= now ||
        j.at("expires_at").integer - j.at("issued_at").integer != 30 || j.at("expires_at").integer > now + 35 ||
        !unhex(j.at("nonce").text, nonce.data(), nonce.size()) || !verify(cfg.broker_key, ticket_payload(j), envelope.at("signature").text)) return false;
    std::lock_guard lock(mutex_);
    for (auto i = seen_.begin(); i != seen_.end();) { if (i->second <= now) i = seen_.erase(i); else ++i; }
    if (seen_.size() >= 1024) return false;
    return seen_.emplace(j.at("nonce").text, j.at("expires_at").integer).second;
  }
};

inline bool registration(const Config &cfg, TlsContext &tls, unsigned port, const Endpoint &local, bool &announced) {
  Fd fd = connect_socket(cfg.broker, IPPROTO_TCP); if (!fd) return false;
  Channel channel(tls, fd.value); if (!channel.handshake(false)) return false;
  WebSocket ws(channel, false); if (!ws.upgrade(cfg.broker.text())) return false;
  Json request = message("register"), reply; request.object["port"] = Json(static_cast<std::int64_t>(port));
  if (!ws.send(request) || !ws.receive(reply, 5) || !schema(reply, {{"version", Json::Integer}, {"type", Json::String}}) || reply.at("type").text != "registered") return false;
  if (!announced) { ready("agent", local); announced = true; }
  while (!stopped) {
    auto until = deadline(5);
    while (!stopped && Clock::now() < until) std::this_thread::sleep_for(std::chrono::milliseconds(100));
    if (stopped) return true;
    if (!ws.send(message("ping")) || !ws.receive(reply, 5) || !schema(reply, {{"version", Json::Integer}, {"type", Json::String}}) || reply.at("type").text != "pong") return false;
  }
  return true;
}
inline void client_session(const Config &cfg, TlsContext &broker_tls, TlsContext &agent_tls, int local) {
  Fd broker = connect_socket(cfg.broker, IPPROTO_TCP); if (!broker) return;
  Channel channel(broker_tls, broker.value); if (!channel.handshake(false)) return;
  WebSocket ws(channel, false); if (!ws.upgrade(cfg.broker.text())) return;
  auto request = message("open"); request.object["agent"] = Json(cfg.target_agent); Json reply;
  if (!ws.send(request) || !ws.receive(reply, 5) || !schema(reply, {{"version", Json::Integer}, {"type", Json::String}, {"endpoint", Json::String}, {"ticket", Json::Object}, {"signature", Json::String}}) || reply.at("type").text != "grant") return;
  Endpoint agent;
  if (!endpoint(reply.at("endpoint").text, agent) || reply.at("ticket").at("agent_key").text != cfg.agent_key) return;
  Fd remote = connect_socket(agent, sctp_protocol); if (!remote) return;
  Channel encrypted(agent_tls, remote.value); if (!encrypted.handshake(false)) return;
  Json proof = Json::obj(); proof.object["version"] = Json(std::int64_t{1}); proof.object["ticket"] = reply.at("ticket"); proof.object["signature"] = reply.at("signature");
  std::string response; Json ack;
  if (!encrypted.frame(encode(proof)) || !encrypted.frame(response, deadline()) || !JsonParser{}.parse(response, ack) ||
      !schema(ack, {{"version", Json::Integer}, {"type", Json::String}}) || ack.at("version").integer != 1 || ack.at("type").text != "ready") return;
  (void)tunnel(encrypted, local);
}
inline int run(const Config &cfg) {
  Fd listener = listen_socket(cfg.listen, cfg.role == "agent" ? sctp_protocol : IPPROTO_TCP);
  if (!listener) { std::fprintf(stderr, "shadow6-cpp: cannot bind %s listener: %s\n", cfg.role.c_str(), std::strerror(errno)); return 1; }
  auto local = socket_endpoint(listener.value);
  std::set<std::string> pins;
  for (const auto &[id, p] : cfg.clients) { (void)id; pins.insert(p.key); }
  if (cfg.role == "broker") for (const auto &[id, p] : cfg.agents) { (void)id; pins.insert(p.key); }
  TlsContext server(cfg.secret, pins), broker(cfg.secret, {cfg.broker_key}), agent(cfg.secret, {cfg.agent_key});
  if (!server.get() || (cfg.role == "client" && !broker.get()) || (cfg.role == "client" && !agent.get()) || (cfg.role == "agent" && !broker.get())) {
    std::fprintf(stderr, "shadow6-cpp: TLS context initialization failed for role %s\n", cfg.role.c_str());
    return 1;
  }
  if (cfg.role == "broker") {
    Broker state(cfg); ready("broker", local);
    serve(listener.value, [&](int fd) { state.handle(server, fd); });
  } else if (cfg.role == "agent") {
    Tickets tickets;
    std::thread control([&] {
      bool announced = false;
      while (!stopped) {
        if (!registration(cfg, broker, local.port, local, announced) && !stopped) {
          std::fputs("shadow6-cpp: broker unavailable or authentication rejected; retrying\n", stderr);
          for (unsigned i = 0; i < 20 && !stopped; ++i) std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
      }
    });
    serve(listener.value, [&](int fd) {
      Channel channel(server, fd); std::string data; Json proof;
      if (!channel.handshake(true) || !channel.frame(data, deadline()) || !JsonParser{}.parse(data, proof) || !tickets.accept(cfg, channel.peer_key(), proof)) return;
      Fd target = connect_socket(cfg.target, IPPROTO_TCP); if (!target) return;
      if (channel.frame(encode(message("ready")))) (void)tunnel(channel, target.value);
    });
    control.join();
  } else {
    ready("client", local);
    serve(listener.value, [&](int fd) { client_session(cfg, broker, agent, fd); });
  }
  return 0;
}
} // namespace shadow6
