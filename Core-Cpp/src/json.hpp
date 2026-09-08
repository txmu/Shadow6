#pragma once
#include <charconv>
#include <cstdint>
#include <map>
#include <string>
#include <string_view>
#include <vector>

namespace shadow6 {
// Deliberately small configuration/control JSON vocabulary. No floating point,
// duplicate keys, implicit coercion or unchecked recursive allocation.
struct Json {
  enum Kind { Null, Boolean, Integer, String, Object, Array } kind{Null};
  std::int64_t integer{};
  std::string text;
  std::map<std::string, Json> object;
  std::vector<Json> array;
  Json() = default;
  explicit Json(std::string v) : kind(String), text(std::move(v)) {}
  explicit Json(const char *v) : Json(std::string(v)) {}
  explicit Json(std::int64_t v) : kind(Integer), integer(v) {}
  static Json obj() { Json j; j.kind = Object; return j; }
  const Json &at(std::string_view key) const {
    static const Json empty;
    auto i = object.find(std::string(key));
    return i == object.end() ? empty : i->second;
  }
};

inline bool ascii(std::string_view s) {
  for (unsigned char c : s) if (c < 32 || c > 126) return false;
  return true;
}
inline bool utf8(std::string_view s) {
  for (std::size_t i = 0; i < s.size();) {
    auto c = static_cast<unsigned char>(s[i++]);
    if (c < 128) continue;
    unsigned n{}, value{}, minimum{};
    if (c >= 0xc2 && c <= 0xdf) { n = 1; value = c & 31U; minimum = 128; }
    else if (c >= 0xe0 && c <= 0xef) { n = 2; value = c & 15U; minimum = 2048; }
    else if (c >= 0xf0 && c <= 0xf4) { n = 3; value = c & 7U; minimum = 65536; }
    else return false;
    for (unsigned k = 0; k < n; ++k) {
      if (i == s.size()) return false;
      c = static_cast<unsigned char>(s[i++]);
      if ((c & 0xc0U) != 0x80U) return false;
      value = (value << 6) | (c & 63U);
    }
    if (value < minimum || value > 0x10ffff || (value >= 0xd800 && value <= 0xdfff)) return false;
  }
  return true;
}

class JsonParser {
  std::string_view input_;
  std::size_t pos_{}, nodes_{};
  void space() { while (pos_ < input_.size() && (input_[pos_] == ' ' || input_[pos_] == '\r' || input_[pos_] == '\n' || input_[pos_] == '\t')) ++pos_; }
  bool take(char c) { space(); if (pos_ == input_.size() || input_[pos_] != c) return false; ++pos_; return true; }
  bool unit(unsigned &v) {
    if (input_.size() - pos_ < 4) return false;
    const auto r = std::from_chars(input_.data() + pos_, input_.data() + pos_ + 4, v, 16);
    if (r.ec != std::errc{} || r.ptr != input_.data() + pos_ + 4) return false;
    pos_ += 4; return true;
  }
  bool string(std::string &s) {
    if (!take('"')) return false;
    while (pos_ < input_.size() && s.size() <= 16384) {
      char c = input_[pos_++];
      if (c == '"') return s.size() <= 16384;
      if (static_cast<unsigned char>(c) < 32) return false;
      if (c != '\\') { s += c; continue; }
      if (pos_ == input_.size()) return false;
      c = input_[pos_++];
      switch (c) {
      case '"': case '\\': case '/': s += c; break;
      case 'b': s += '\b'; break; case 'f': s += '\f'; break;
      case 'n': s += '\n'; break; case 'r': s += '\r'; break; case 't': s += '\t'; break;
      case 'u': {
        unsigned v{}; if (!unit(v)) return false;
        if (v >= 0xd800 && v <= 0xdbff) {
          if (input_.substr(pos_, 2) != "\\u") return false;
          pos_ += 2; unsigned low{};
          if (!unit(low) || low < 0xdc00 || low > 0xdfff) return false;
          v = 0x10000 + ((v - 0xd800) << 10) + low - 0xdc00;
        } else if (v >= 0xdc00 && v <= 0xdfff) return false;
        if (v < 128) s += static_cast<char>(v);
        else {
          if (v >= 65536) s += static_cast<char>(0xf0U | (v >> 18));
          else if (v >= 2048) s += static_cast<char>(0xe0U | (v >> 12));
          else s += static_cast<char>(0xc0U | (v >> 6));
          if (v >= 65536) s += static_cast<char>(0x80U | ((v >> 12) & 63U));
          if (v >= 2048) s += static_cast<char>(0x80U | ((v >> 6) & 63U));
          s += static_cast<char>(0x80U | (v & 63U));
        }
        break;
      }
      default: return false;
      }
    }
    return false;
  }
  bool value(Json &j, unsigned depth) {
    if (depth > 16 || ++nodes_ > 4096) return false;
    space(); if (pos_ == input_.size()) return false;
    char c = input_[pos_];
    if (c == '"') { j.kind = Json::String; return string(j.text); }
    if (c == '{' || c == '[') {
      ++pos_; j.kind = c == '{' ? Json::Object : Json::Array;
      char close = c == '{' ? '}' : ']';
      if (take(close)) return true;
      do {
        std::string key;
        if (c == '{' && (!string(key) || !take(':') || j.object.contains(key))) return false;
        Json child; if (!value(child, depth + 1)) return false;
        if (c == '{') j.object.emplace(std::move(key), std::move(child));
        else j.array.push_back(std::move(child));
        if (take(close)) return true;
      } while (take(','));
      return false;
    }
    for (auto token : {std::string_view("null"), std::string_view("true"), std::string_view("false")}) {
      if (input_.substr(pos_, token.size()) == token) {
        pos_ += token.size(); j.kind = token == "null" ? Json::Null : Json::Boolean;
        j.integer = token == "true"; return true;
      }
    }
    auto start = pos_;
    if (c == '-') ++pos_;
    if (pos_ == input_.size() || input_[pos_] < '0' || input_[pos_] > '9') return false;
    if (input_[pos_] == '0') ++pos_;
    else while (pos_ < input_.size() && input_[pos_] >= '0' && input_[pos_] <= '9') ++pos_;
    auto r = std::from_chars(input_.data() + start, input_.data() + pos_, j.integer);
    j.kind = Json::Integer;
    return r.ec == std::errc{} && j.integer >= -9007199254740991LL && j.integer <= 9007199254740991LL;
  }
public:
  bool parse(std::string_view data, Json &out) {
    if (data.empty() || data.size() > 1048576 || !utf8(data)) return false;
    input_ = data; pos_ = nodes_ = 0; out = Json{};
    if (!value(out, 0)) return false;
    space(); return pos_ == input_.size();
  }
};

inline std::string quote(std::string_view s) {
  std::string out = "\"";
  const char *hex = "0123456789abcdef";
  for (unsigned char c : s) {
    if (c == '"' || c == '\\') { out += '\\'; out += static_cast<char>(c); }
    else if (c < 32) { out += "\\u00"; out += hex[c >> 4]; out += hex[c & 15]; }
    else out += static_cast<char>(c);
  }
  return out + '"';
}
inline std::string encode(const Json &j) {
  switch (j.kind) {
  case Json::Null: return "null";
  case Json::Boolean: return j.integer ? "true" : "false";
  case Json::Integer: return std::to_string(j.integer);
  case Json::String: return quote(j.text);
  case Json::Object: {
    std::string out = "{"; bool first = true;
    for (const auto &[key, val] : j.object) { if (!first) out += ','; first = false; out += quote(key) + ':' + encode(val); }
    return out + '}';
  }
  case Json::Array: {
    std::string out = "["; bool first = true;
    for (const auto &val : j.array) { if (!first) out += ','; first = false; out += encode(val); }
    return out + ']';
  }
  }
  return "null";
}
inline bool schema(const Json &j, std::initializer_list<std::pair<const char *, Json::Kind>> fields) {
  if (j.kind != Json::Object || j.object.size() != fields.size()) return false;
  for (auto [key, kind] : fields) if (j.at(key).kind != kind || !j.object.contains(key)) return false;
  return true;
}
inline Json message(const char *type) {
  Json j = Json::obj(); j.object["version"] = Json(std::int64_t{1}); j.object["type"] = Json(type); return j;
}
} // namespace shadow6
