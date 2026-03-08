#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <string_view>
#include <vector>

namespace blook {

struct PatternByte {
  uint8_t value;
  bool is_wildcard;
};

namespace detail {

constexpr bool is_hex_char(char c) {
  return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') ||
         (c >= 'A' && c <= 'F');
}

constexpr uint8_t hex_char_to_value(char c) {
  if (c >= '0' && c <= '9')
    return c - '0';
  if (c >= 'a' && c <= 'f')
    return c - 'a' + 10;
  if (c >= 'A' && c <= 'F')
    return c - 'A' + 10;
  return 0;
}

constexpr std::optional<uint8_t> parse_hex_byte(char high, char low) {
  if (!is_hex_char(high) || !is_hex_char(low))
    return std::nullopt;
  return (hex_char_to_value(high) << 4) | hex_char_to_value(low);
}

constexpr size_t skip_whitespace_and_separators(std::string_view sv,
                                                 size_t pos) {
  while (pos < sv.size() &&
         (sv[pos] == ' ' || sv[pos] == '\t' || sv[pos] == ',' ||
          sv[pos] == '\n' || sv[pos] == '\r')) {
    pos++;
  }
  return pos;
}

} // namespace detail

// 支持格式：
// - "aabbcc"
// - "aa bb cc"
// - "aa,bb,cc"
// - "0xaa, 0xbb, 0xcc"
// - "aa??12" (通配符)
inline std::vector<PatternByte> parse_pattern(std::string_view pattern) {
  std::vector<PatternByte> result;
  size_t pos = 0;

  while (pos < pattern.size()) {
    pos = detail::skip_whitespace_and_separators(pattern, pos);
    if (pos >= pattern.size())
      break;

    if (pos + 1 < pattern.size() && pattern[pos] == '0' &&
        (pattern[pos + 1] == 'x' || pattern[pos + 1] == 'X')) {
      pos += 2;
    }

    if (pos + 1 < pattern.size() && pattern[pos] == '?' &&
        pattern[pos + 1] == '?') {
      result.push_back({0, true});
      pos += 2;
      continue;
    }

    if (pos + 1 < pattern.size()) {
      auto byte = detail::parse_hex_byte(pattern[pos], pattern[pos + 1]);
      if (byte.has_value()) {
        result.push_back({byte.value(), false});
        pos += 2;
      } else {
        pos++;
      }
    } else {
      break;
    }
  }

  return result;
}

inline std::vector<uint8_t>
pattern_to_bytes(const std::vector<PatternByte> &pattern) {
  std::vector<uint8_t> result;
  for (const auto &pb : pattern) {
    // 通配符转换为 KMP 的通配符标记 0xBC
    result.push_back(pb.is_wildcard ? 0xBC : pb.value);
  }
  return result;
}

// 检查 pattern 是否包含通配符
inline bool has_wildcard(const std::vector<PatternByte> &pattern) {
  for (const auto &pb : pattern) {
    if (pb.is_wildcard)
      return true;
  }
  return false;
}

// 带通配符的模式匹配
inline bool match_pattern_with_wildcard(const uint8_t *data, size_t data_size,
                                        const std::vector<PatternByte> &pattern) {
  if (pattern.size() > data_size)
    return false;

  for (size_t i = 0; i < pattern.size(); i++) {
    if (!pattern[i].is_wildcard && data[i] != pattern[i].value) {
      return false;
    }
  }
  return true;
}

} // namespace blook
