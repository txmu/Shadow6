#include "src/runtime.hpp"
#include <cstdlib>
#include <sys/wait.h>

using namespace shadow6;
static void require(bool ok, const char *what) {
  if (!ok) { std::fprintf(stderr, "FAIL: %s\n", what); std::exit(1); }
}
static Json make_ticket(const Config &cfg, const std::string &client_key) {
  Json j = Json::obj();
  j.object["version"] = Json(std::int64_t{1}); j.object["client"] = Json("client-1");
  j.object["client_key"] = Json(client_key); j.object["agent"] = Json(cfg.id);
  j.object["agent_key"] = Json(public_hex(private_key(cfg.secret).get()));
  j.object["issued_at"] = Json(epoch()); j.object["expires_at"] = Json(epoch() + 30);
  j.object["nonce"] = Json(std::string(64, 'a')); return j;
}
static Json make_proof(const Json &ticket, const std::string &secret) {
  Json j = Json::obj(); j.object["version"] = Json(std::int64_t{1}); j.object["ticket"] = ticket;
  j.object["signature"] = Json(sign(private_key(secret).get(), ticket_payload(ticket))); return j;
}
static void accept_burst() {
  Endpoint bind;
  require(endpoint("127.0.0.1:1", bind), "burst loopback address");
  reinterpret_cast<sockaddr_in *>(&bind.address)->sin_port = 0;
  Fd listener = listen_socket(bind, IPPROTO_TCP);
  require(static_cast<bool>(listener), "burst listener");
  auto address = socket_endpoint(listener.value);
  auto child = fork();
  require(child >= 0, "burst server fork");
  if (child == 0) {
    std::signal(SIGALRM, [](int) { stopped = 1; });
    std::signal(SIGTERM, [](int) { stopped = 1; });
    alarm(10);
    serve(listener.value, [](int fd) { (void)plain_write(fd, "accepted"); });
    _exit(0);
  }
  bool complete = true;
  for (unsigned i = 0; i < 64; ++i) {
    Fd connection = connect_socket(address, IPPROTO_TCP);
    if (!connection || !wait_fd(connection.value, POLLIN, deadline(2))) { complete = false; break; }
    char reply[8];
    if (recv(connection.value, reply, sizeof(reply), MSG_WAITALL) != 8 || std::string_view(reply, 8) != "accepted") { complete = false; break; }
  }
  kill(child, SIGTERM);
  int status = 0;
  require(waitpid(child, &status, 0) == child && WIFEXITED(status) && WEXITSTATUS(status) == 0, "burst server shutdown");
  require(complete, "64 TCP accepts are not capped at 16 per second");
}
static int unit_tests() {
  HandshakeBudget budget;
  auto budget_now = Clock::now();
  for (unsigned i = 0; i < 64; ++i) require(budget.take(budget_now), "TLS reconnect burst");
  require(!budget.take(budget_now), "TLS work stays rate bounded");
  require(budget.take(budget_now + std::chrono::milliseconds(63)), "TLS budget refills continuously");
  require(!budget.take(budget_now + std::chrono::milliseconds(63)), "TLS refill cannot mint extra permits");
  accept_burst();
  Json j;
  for (auto bad : {"", "{,}", "{\"x\":1,}", "{\"x\":1 \"y\":2}", "[1,]", "01", "1.0", "1e3", "9007199254740992", "{\"x\":1,\"x\":2}", "{\"x\":1,\"\\u0078\":2}", "\"\\ud800\"", "\"\\udfff\"", "{} {}"}) require(!JsonParser{}.parse(bad, j), "strict JSON rejection");
  require(!JsonParser{}.parse(std::string("\"\xff\"", 3), j), "invalid UTF-8");
  require(!JsonParser{}.parse(std::string(17, '[') + "0" + std::string(17, ']'), j), "depth limit");
  require(!JsonParser{}.parse("\"" + std::string(16385, 'x') + "\"", j), "string bound");
  require(!JsonParser{}.parse(std::string(1048577, ' '), j), "document bound");
  require(JsonParser{}.parse("{\"hello\":\"\\ud83d\\ude00\",\"number\":9007199254740991}", j), "valid Unicode");
  Json again; require(JsonParser{}.parse(encode(j), again) && encode(j) == encode(again), "canonical roundtrip");
  Endpoint ep;
  require(endpoint("[::1]:12", ep) && ep.loopback, "IPv6 endpoint");
  for (auto address : {"host:12", "127.0.0.1:99999", "127.0.0.1:0", "[::ffff:127.0.0.1]:12", "224.0.0.1:12", "127.0.0.1:12junk"}) require(!endpoint(address, ep), "endpoint rejection");
  std::string broker_secret(64, '1'), agent_secret(64, '2'), client_secret(64, '3');
  Config cfg; cfg.id = "agent-1"; cfg.secret = agent_secret; cfg.broker_key = public_hex(private_key(broker_secret).get());
  auto client_key = public_hex(private_key(client_secret).get()); cfg.clients["client-1"] = Peer{client_key, {}};
  auto ticket = make_ticket(cfg, client_key); auto proof = make_proof(ticket, broker_secret);
  Tickets replay;
  require(replay.accept(cfg, client_key, proof), "valid broker ticket");
  require(!replay.accept(cfg, client_key, proof), "ticket replay");
  for (auto field : {"client", "client_key", "agent", "agent_key", "nonce"}) {
    auto bad = ticket; bad.object[field] = Json("wrong"); Tickets seen;
    require(!seen.accept(cfg, client_key, make_proof(bad, broker_secret)), "ticket identity binding");
  }
  for (int change : {-120, 120}) {
    auto bad = ticket; bad.object["issued_at"] = Json(epoch() + change); bad.object["expires_at"] = Json(epoch() + change + 30); Tickets seen;
    require(!seen.accept(cfg, client_key, make_proof(bad, broker_secret)), "ticket clock window");
  }
  { Tickets seen; auto bad = proof; bad.object["signature"] = Json(std::string(128, '0')); require(!seen.accept(cfg, client_key, bad), "ticket signature"); }
  { Tickets seen; auto bad = ticket; bad.object["extra"] = Json("x"); require(!seen.accept(cfg, client_key, make_proof(bad, broker_secret)), "unknown ticket schema"); }
  { Tickets seen; require(!seen.accept(cfg, cfg.broker_key, proof), "ticket TLS peer binding"); }
  Tickets concurrent; std::atomic<unsigned> accepted{0}; std::array<std::thread, 8> threads;
  for (auto &thread : threads) thread = std::thread([&] { if (concurrent.accept(cfg, client_key, proof)) ++accepted; });
  for (auto &thread : threads) thread.join();
  require(accepted == 1, "atomic replay protection");
  std::puts("[PASS] C++ strict JSON, endpoint, signature, expiry and concurrent replay tests"); return 0;
}
static int probe(const char *path, const std::string &mode) {
  Config cfg; require(load_config(path, cfg), "probe config");
  TlsContext tls(cfg.secret, {cfg.broker_key});
  Fd fd = connect_socket(cfg.broker, IPPROTO_TCP); require(static_cast<bool>(fd), "probe connect");
  Channel channel(tls, fd.value);
  if (mode == "reject-tls") {
    bool rejected = !channel.handshake(false);
    if (!rejected) { WebSocket ws(channel, false); rejected = !ws.upgrade(cfg.broker.text()); }
    require(rejected, "reject untrusted TLS identity"); return 0;
  }
  require(channel.handshake(false), "probe TLS");
  WebSocket ws(channel, false); require(ws.upgrade(cfg.broker.text()), "probe WSS");
  Json request = message("open"); request.object["agent"] = Json(cfg.target_agent);
  if (mode == "unmasked") {
    auto data = encode(request); std::string frame(1, static_cast<char>(0x81)); frame += static_cast<char>(data.size()); frame += data;
    require(channel.write(frame), "send invalid mask");
  } else {
    if (mode == "unknown") request.object["extra"] = Json("x");
    else if (mode == "version") request.object["version"] = Json(std::int64_t{2});
    require(ws.send(request), "probe request");
  }
  Json response; bool got = ws.receive(response, 3);
  if (mode == "denied") require(got && response.at("type").text == "denied", "broker RBAC denial");
  else require(!got, "malformed control connection closed");
  return 0;
}
int main(int argc, char **argv) {
  std::signal(SIGPIPE, SIG_IGN);
  if (argc == 4 && std::string_view(argv[1]) == "--probe") return probe(argv[2], argv[3]);
  return unit_tests();
}
