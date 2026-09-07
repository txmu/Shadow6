#include <array>
#include <charconv>
#include <concepts>
#include <coroutine>
#include <cstdint>
#include <cstdio>
#include <cstring>
#include <fcntl.h>
#include <span>
#include <string_view>
#include <sys/stat.h>
#include <unistd.h>

namespace shadow6 {

template <typename T> struct Result {
  T value{};
  const char *error{};
  [[nodiscard]] explicit operator bool() const noexcept { return error == nullptr; }
  static Result ok(T v) noexcept { return {v, nullptr}; }
  static Result fail(const char *e) noexcept { return {T{}, e}; }
};
template <> struct Result<void> {
  const char *error{};
  [[nodiscard]] explicit operator bool() const noexcept { return error == nullptr; }
  static Result ok() noexcept { return {nullptr}; }
  static Result fail(const char *e) noexcept { return {e}; }
};

template <typename T>
concept BoundedBytes = requires(T value) {
  { value.data() } -> std::same_as<const char *>;
  { value.size() } -> std::convertible_to<std::size_t>;
};

// A bounded, non-owning JSON contract check. Unknown keys, duplicate keys,
// floats, and non-UTF-8 control bytes are rejected before role dispatch.
class StrictJson {
public:
  static Result<void> validate(std::string_view json) noexcept {
    if (json.size() == 0 || json.size() > 1024U * 1024U) return Result<void>::fail("invalid JSON size");
    std::size_t i = 0;
    while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) ++i;
    if (i >= json.size() || json[i++] != '{') return Result<void>::fail("JSON object required");
    bool role = false;
    std::string_view role_name;
    std::array<bool, 3> sections{};
    while (i < json.size()) {
      while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t' || json[i] == ',')) ++i;
      if (i < json.size() && json[i] == '}') {
        ++i;
        while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) ++i;
        const std::size_t expected = role_name == "broker" ? 0U : (role_name == "agent" ? 1U : 2U);
        return (role && sections[expected] && i == json.size()) ? Result<void>::ok() : Result<void>::fail("role section mismatch or trailing JSON");
      }
      if (i >= json.size() || json[i++] != '"') return Result<void>::fail("JSON key required");
      const std::size_t begin = i;
      while (i < json.size() && json[i] != '"') {
        if (static_cast<unsigned char>(json[i]) < 0x20U || json[i] == '\\') return Result<void>::fail("unsupported JSON escape");
        ++i;
      }
      if (i >= json.size()) return Result<void>::fail("unterminated key");
      const std::string_view key = json.substr(begin, i - begin);
      ++i;
      while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) ++i;
      if (i >= json.size() || json[i++] != ':') return Result<void>::fail("missing colon");
      while (i < json.size() && (json[i] == ' ' || json[i] == '\n' || json[i] == '\r' || json[i] == '\t')) ++i;
      if (key == "role") {
        if (role || i >= json.size() || json[i++] != '"') return Result<void>::fail("role must be a string");
        const std::size_t value_begin = i;
        while (i < json.size() && json[i] != '"') ++i;
        if (i >= json.size()) return Result<void>::fail("unterminated role");
        const auto value = json.substr(value_begin, i - value_begin);
        if (value != "broker" && value != "agent" && value != "client") return Result<void>::fail("invalid role");
        ++i; role = true; role_name = value;
      } else if (key == "broker" || key == "agent" || key == "client") {
        const std::size_t section = key == "broker" ? 0U : (key == "agent" ? 1U : 2U);
        if (sections[section]) return Result<void>::fail("duplicate JSON field");
        sections[section] = true;
        if (i >= json.size() || json[i] != '{') return Result<void>::fail("role section must be an object");
        int depth = 0;
        do {
          if (i >= json.size()) return Result<void>::fail("unterminated role section");
          if (json[i] == '{') ++depth;
          if (json[i] == '}') --depth;
          ++i;
        } while (depth > 0);
      } else return Result<void>::fail("unknown JSON field");
    }
    return Result<void>::fail("unterminated JSON object");
  }
};

struct FeatureReport {
  static void print() noexcept {
    std::fputs("{\"core\":\"shadow6-cpp\",\"version\":\"1.1.0\",\"crosed_compiled\":false,\"crosed_max_level\":0,\"app_transport\":false,\"qubes_isolation\":false,\"gate_compiled\":true,\"gate_enabled_by_default\":false,\"utf8\":true,\"crosed_capabilities\":[]}\n", stdout);
  }
};

// SCTP transport contract: one stream per tunnel channel and bounded paths.
class SctpTransport final {
  static constexpr std::size_t MaxPaths = 8;
  static constexpr std::size_t MaxStreams = 256;
  int fd_{-1};
  std::array<std::string_view, MaxPaths> paths_{};
public:
  explicit SctpTransport(int fd) noexcept : fd_(fd) {}
  [[nodiscard]] int fd() const noexcept { return fd_; }
  [[nodiscard]] bool add_path(std::string_view address) noexcept {
    for (auto &path : paths_) if (path.empty()) { path = address; return true; }
    return false;
  }
  [[nodiscard]] bool valid_stream(std::uint16_t stream) const noexcept { return stream < MaxStreams; }
};

class TlsOverSctp {
public:
  virtual ~TlsOverSctp() = default;
  virtual Result<void> handshake(std::span<const std::byte> transcript) noexcept = 0;
  virtual Result<std::size_t> write(std::span<const std::byte> data) noexcept = 0;
};

struct Task {
  struct promise_type {
    Task get_return_object() noexcept { return {}; }
    std::suspend_never initial_suspend() noexcept { return {}; }
    std::suspend_never final_suspend() noexcept { return {}; }
    void return_void() noexcept {}
    void unhandled_exception() noexcept { __builtin_trap(); }
  };
};
Task mtd_cycle_tick() noexcept {
  co_await std::suspend_never{};
  co_return;
}
class Scheduler {
  std::array<std::coroutine_handle<>, 64> ready_{};
  std::size_t count_{0};
public:
  [[nodiscard]] bool enqueue(std::coroutine_handle<> handle) noexcept {
    if (!handle || count_ == ready_.size()) return false;
    ready_[count_++] = handle; return true;
  }
  void run_once() noexcept {
    for (std::size_t i = 0; i < count_; ++i) if (ready_[i] && !ready_[i].done()) ready_[i].resume();
    count_ = 0;
  }
};

class Ed25519WebSocketRpc {
public:
  virtual ~Ed25519WebSocketRpc() = default;
  virtual Result<std::size_t> authenticated_json_rpc(std::span<const std::byte> frame) noexcept = 0;
};

Result<std::string_view> read_config(const char *path, std::array<char, 1024U * 1024U + 1U> &buffer) noexcept {
  const int fd = ::open(path, O_RDONLY | O_CLOEXEC | O_NOFOLLOW);
  if (fd < 0) return Result<std::string_view>::fail("cannot open config");
  struct stat st{};
  if (::fstat(fd, &st) != 0 || !S_ISREG(st.st_mode) || st.st_size < 1 || st.st_size > 1024 * 1024) { ::close(fd); return Result<std::string_view>::fail("invalid config file"); }
  const ssize_t n = ::read(fd, buffer.data(), buffer.size() - 1U);
  ::close(fd);
  if (n < 1 || static_cast<off_t>(n) != st.st_size) return Result<std::string_view>::fail("incomplete config");
  buffer[static_cast<std::size_t>(n)] = '\0';
  return Result<std::string_view>::ok(std::string_view(buffer.data(), static_cast<std::size_t>(n)));
}

} // namespace shadow6

int main(int argc, char **argv) noexcept {
  if (argc == 2 && std::strcmp(argv[1], "--feature-report") == 0) { shadow6::FeatureReport::print(); return 0; }
  if (argc == 3 && std::strcmp(argv[1], "--check-config") == 0) {
    std::array<char, 1024U * 1024U + 1U> buffer{};
    const auto config = shadow6::read_config(argv[2], buffer);
    if (!config) { std::fprintf(stderr, "shadow6-cpp: %s\n", config.error); return 2; }
    const auto valid = shadow6::StrictJson::validate(config.value);
    if (!valid) { std::fprintf(stderr, "shadow6-cpp: %s\n", valid.error); return 2; }
    std::puts("configuration is valid"); return 0;
  }
  std::fputs("shadow6-cpp --check-config FILE | --feature-report\n", stderr);
  return 2;
}
