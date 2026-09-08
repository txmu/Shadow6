#include "runtime.hpp"

namespace shadow6 {
bool write_new(const std::string &path, const std::string &data) {
  Fd fd(open(path.c_str(), O_WRONLY | O_CREAT | O_EXCL | O_CLOEXEC | O_NOFOLLOW, 0600));
  if (!fd) return false;
  std::size_t done = 0;
  while (done < data.size()) {
    auto n = write(fd.value, data.data() + done, data.size() - done);
    if (n < 0 && errno == EINTR) continue;
    if (n <= 0) return false;
    done += static_cast<std::size_t>(n);
  }
  return fsync(fd.value) == 0;
}
int demo(const char *directory) {
  if (mkdir(directory, 0700) != 0) { std::fputs("demo requires a new directory\n", stderr); return 2; }
  std::array<std::string, 3> secret, pub;
  for (unsigned i = 0; i < 3; ++i) {
    std::array<unsigned char, 32> seed{};
    if (RAND_bytes(seed.data(), seed.size()) != 1) return 1;
    secret[i] = hex(seed.data(), seed.size()); pub[i] = public_hex(private_key(secret[i]).get());
    OPENSSL_cleanse(seed.data(), seed.size()); if (pub[i].empty()) return 1;
  }
  std::array<std::string, 3> configs{{
    "{\"role\":\"broker\",\"broker\":{\"listen_addr\":\"127.0.0.1:18443\",\"private_key\":" + quote(secret[0]) + ",\"agents\":[{\"id\":\"agent-1\",\"pubkey\":" + quote(pub[1]) + "}],\"clients\":[{\"id\":\"client-1\",\"pubkey\":" + quote(pub[2]) + ",\"allowed_agents\":[\"agent-1\"]}]}}",
    "{\"role\":\"agent\",\"agent\":{\"id\":\"agent-1\",\"private_key\":" + quote(secret[1]) + ",\"broker_addr\":\"127.0.0.1:18443\",\"broker_pubkey\":" + quote(pub[0]) + ",\"listen_addr\":\"127.0.0.1:18444\",\"target_addr\":\"127.0.0.1:22\",\"client_pubkeys\":{\"client-1\":" + quote(pub[2]) + "},\"transport\":\"sctp\"}}",
    "{\"role\":\"client\",\"client\":{\"id\":\"client-1\",\"private_key\":" + quote(secret[2]) + ",\"broker_addr\":\"127.0.0.1:18443\",\"broker_pubkey\":" + quote(pub[0]) + ",\"listen_addr\":\"127.0.0.1:18080\",\"target_agent\":\"agent-1\",\"agent_pubkey\":" + quote(pub[1]) + ",\"transport\":\"sctp\"}}"
  }};
  for (unsigned i = 0; i < 3; ++i) {
    Config c; Json j;
    if (!JsonParser{}.parse(configs[i], j) || !parse_config(j, c) || !write_new(std::string(directory) + "/" + c.role + ".json", configs[i] + "\n")) return 1;
  }
  std::puts("Created broker.json, agent.json and client.json (0600); no services started."); return 0;
}
} // namespace shadow6

int main(int argc, char **argv) {
  using namespace shadow6;
  std::signal(SIGPIPE, SIG_IGN);
  std::signal(SIGTERM, [](int) { stopped = 1; }); std::signal(SIGINT, [](int) { stopped = 1; });
  if (argc == 2 && std::strcmp(argv[1], "--feature-report") == 0) { std::puts(features); return 0; }
  if (argc == 3 && std::strcmp(argv[1], "--init-demo") == 0) return demo(argv[2]);
  if (argc == 2 && std::strcmp(argv[1], "--keygen") == 0) {
    std::array<unsigned char, 32> seed{}; if (RAND_bytes(seed.data(), seed.size()) != 1) return 1;
    auto secret = hex(seed.data(), seed.size()); OPENSSL_cleanse(seed.data(), seed.size());
    auto pub = public_hex(private_key(secret).get()); if (pub.empty()) return 1;
    std::printf("{\"private_key\":\"%s\",\"public_key\":\"%s\"}\n", secret.c_str(), pub.c_str()); return 0;
  }
  bool check = argc == 3 && std::strcmp(argv[1], "--check-config") == 0;
  bool config = (argc == 3 || argc == 4) && std::strcmp(argv[1], "--config") == 0;
  if (config && argc == 4) { if (std::strcmp(argv[3], "--check-config") != 0) return 2; check = true; }
  if (check || config) {
    Config cfg;
    if (!load_config(argv[2], cfg)) { std::fputs("shadow6-cpp: invalid configuration or unsafe file (requires owned regular 0600 file)\n", stderr); return 2; }
    if (check) { std::puts("configuration is valid"); return 0; }
    return run(cfg);
  }
  std::fputs("shadow6-cpp --config FILE [--check-config] | --check-config FILE | --feature-report | --keygen | --init-demo NEW_DIRECTORY\n", stderr);
  return 2;
}
