#include "util/StrHelpers.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <format>
#include <limits>
#include <ranges>

namespace esptool::text {
namespace {

[[nodiscard]] int HexValue(char value) noexcept {
  if (value >= '0' && value <= '9') {
    return value - '0';
  }
  if (value >= 'a' && value <= 'f') {
    return value - 'a' + 10;
  }
  if (value >= 'A' && value <= 'F') {
    return value - 'A' + 10;
  }
  return -1;
}

[[nodiscard]] bool IsSpace(char value) noexcept {
  return value == ' ' || value == '\t' || value == '\r' || value == '\n' ||
         value == '\f' || value == '\v';
}

[[nodiscard]] char FoldAscii(char value) noexcept {
  return (value >= 'A' && value <= 'Z') ? static_cast<char>(value - 'A' + 'a')
                                        : value;
}

}  // namespace

std::string ToUtf8(std::wstring_view value) {
  if (value.empty()) {
    return {};
  }
  const int required = WideCharToMultiByte(CP_UTF8, 0, value.data(),
                                           static_cast<int>(value.size()),
                                           nullptr, 0, nullptr, nullptr);
  if (required <= 0) {
    return {};
  }
  std::string result(static_cast<std::size_t>(required), '\0');
  WideCharToMultiByte(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), required, nullptr, nullptr);
  return result;
}

std::wstring ToUtf16(std::string_view value) {
  if (value.empty()) {
    return {};
  }
  const int required = MultiByteToWideChar(
      CP_UTF8, 0, value.data(), static_cast<int>(value.size()), nullptr, 0);
  if (required <= 0) {
    return {};
  }
  std::wstring result(static_cast<std::size_t>(required), L'\0');
  MultiByteToWideChar(CP_UTF8, 0, value.data(), static_cast<int>(value.size()),
                      result.data(), required);
  return result;
}

std::string_view Trim(std::string_view value) noexcept {
  std::size_t begin = 0;
  std::size_t end = value.size();
  while (begin < end && IsSpace(value[begin])) {
    ++begin;
  }
  while (end > begin && IsSpace(value[end - 1])) {
    --end;
  }
  return value.substr(begin, end - begin);
}

std::vector<std::string> Split(std::string_view value, char separator) {
  std::vector<std::string> parts;
  std::size_t start = 0;
  while (start <= value.size()) {
    const std::size_t position = value.find(separator, start);
    const std::size_t stop =
        position == std::string_view::npos ? value.size() : position;
    const std::string_view field = Trim(value.substr(start, stop - start));
    if (!field.empty()) {
      parts.emplace_back(field);
    }
    if (position == std::string_view::npos) {
      break;
    }
    start = position + 1;
  }
  return parts;
}

std::string Join(std::span<const std::string> parts,
                 std::string_view separator) {
  std::string result;
  for (std::size_t index = 0; index < parts.size(); ++index) {
    if (index != 0) {
      result.append(separator);
    }
    result.append(parts[index]);
  }
  return result;
}

bool EqualsIgnoreCase(std::string_view left, std::string_view right) noexcept {
  return left.size() == right.size() &&
         std::ranges::equal(left, right, [](char a, char b) {
           return FoldAscii(a) == FoldAscii(b);
         });
}

std::string ToLowerAscii(std::string_view value) {
  std::string result(value);
  std::ranges::transform(result, result.begin(), FoldAscii);
  return result;
}

bool ParseUnsigned(std::string_view value, std::uint64_t& out) noexcept {
  const std::string_view trimmed = Trim(value);
  if (trimmed.empty()) {
    return false;
  }
  std::uint64_t basis = 10;
  std::size_t index = 0;
  if (trimmed.size() > 2 && trimmed[0] == '0' &&
      (trimmed[1] == 'x' || trimmed[1] == 'X')) {
    basis = 16;
    index = 2;
  }
  if (index >= trimmed.size()) {
    return false;
  }
  std::uint64_t accumulator = 0;
  for (; index < trimmed.size(); ++index) {
    const int digit = HexValue(trimmed[index]);
    const int limit = basis == 16 ? 15 : 9;
    if (digit < 0 || digit > limit) {
      return false;
    }
    if (accumulator > (std::numeric_limits<std::uint64_t>::max() -
                       static_cast<std::uint64_t>(digit)) /
                          basis) {
      return false;
    }
    accumulator = accumulator * basis + static_cast<std::uint64_t>(digit);
  }
  out = accumulator;
  return true;
}

// Writes 16 string-order hex pairs. Does not apply Windows mixed-endian
// GUID field swaps. FormatGuid matches this order.
bool ParseGuid(std::string_view value,
               std::span<std::uint8_t, kGuidOctets> out_bytes) noexcept {
  std::string_view body = Trim(value);
  if (body.size() >= 2 && body.front() == '{' && body.back() == '}') {
    body = body.substr(1, body.size() - 2);
  }
  std::string compact;
  compact.reserve(kGuidOctets * 2);
  for (const char character : body) {
    if (character == '-') {
      continue;
    }
    if (HexValue(character) < 0) {
      return false;
    }
    compact.push_back(character);
  }
  if (compact.size() != kGuidOctets * 2) {
    return false;
  }
  for (std::size_t index = 0; index < kGuidOctets; ++index) {
    const int high = HexValue(compact[index * 2]);
    const int low = HexValue(compact[index * 2 + 1]);
    out_bytes[index] = static_cast<std::uint8_t>((high << 4) | low);
  }
  return true;
}

std::string FormatGuid(std::span<const std::uint8_t, kGuidOctets> bytes) {
  std::array<char, 40> buffer{};
  std::snprintf(
      buffer.data(), buffer.size(),
      "{%02x%02x%02x%02x-%02x%02x-%02x%02x-%02x%02x-%02x%02x%02x%02x%02x%02x}",
      bytes[0], bytes[1], bytes[2], bytes[3], bytes[4], bytes[5], bytes[6],
      bytes[7], bytes[8], bytes[9], bytes[10], bytes[11], bytes[12], bytes[13],
      bytes[14], bytes[15]);
  return buffer.data();
}

std::string Win32Message(std::string_view prefix, unsigned error) {
  return std::format("{} (error {})", prefix, error);
}

}  // namespace esptool::text
