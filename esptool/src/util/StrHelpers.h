#pragma once

#include <cstddef>
#include <cstdint>
#include <span>
#include <string>
#include <string_view>
#include <vector>

namespace esptool::text {

constexpr std::size_t kGuidOctets = 16;

// UTF-16 to UTF-8 and back. Invalid sequences are replaced rather than
// throwing.
[[nodiscard]] std::string ToUtf8(std::wstring_view value);
[[nodiscard]] std::wstring ToUtf16(std::string_view value);

// Trims ASCII whitespace from both ends.
[[nodiscard]] std::string_view Trim(std::string_view value) noexcept;

// Splits on a single character, skipping empty fields.
[[nodiscard]] std::vector<std::string> Split(std::string_view value,
                                             char separator);

[[nodiscard]] std::string Join(std::span<const std::string> parts,
                               std::string_view separator);

// Case-insensitive equality for ASCII identifiers.
[[nodiscard]] bool EqualsIgnoreCase(std::string_view left,
                                    std::string_view right) noexcept;

[[nodiscard]] std::string ToLowerAscii(std::string_view value);

// Parses an unsigned integer. Accepts decimal and 0x-prefixed hexadecimal.
[[nodiscard]] bool ParseUnsigned(std::string_view value,
                                 std::uint64_t& out) noexcept;

// Parses a GUID in registry-brace form, for example "{a1b2c3d4-...}".
[[nodiscard]] bool ParseGuid(
    std::string_view value,
    std::span<std::uint8_t, kGuidOctets> out_bytes) noexcept;

[[nodiscard]] std::string FormatGuid(
    std::span<const std::uint8_t, kGuidOctets> bytes);

// "prefix (error N)" — same shape as the former per-TU Win32Message copies.
[[nodiscard]] std::string Win32Message(std::string_view prefix, unsigned error);

}  // namespace esptool::text
