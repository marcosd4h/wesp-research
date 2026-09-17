#include <doctest.h>

#include "util/StrHelpers.h"

#include <array>
#include <cstdint>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

using esptool::text::EqualsIgnoreCase;
using esptool::text::FormatGuid;
using esptool::text::Join;
using esptool::text::kGuidOctets;
using esptool::text::ParseGuid;
using esptool::text::ParseUnsigned;
using esptool::text::Split;
using esptool::text::ToLowerAscii;
using esptool::text::ToUtf16;
using esptool::text::ToUtf8;
using esptool::text::Trim;

namespace {

constexpr char kEAcuteUtf8[] = "\xC3\xA9";

[[nodiscard]] std::array<std::uint8_t, kGuidOctets> SampleGuidBytes() {
  return {0xa1, 0xb2, 0xc3, 0xd4, 0xe5, 0xf6, 0x78, 0x90,
          0xab, 0xcd, 0xef, 0x01, 0x23, 0x45, 0x67, 0x89};
}

}  // namespace

TEST_CASE("ToUtf8 and ToUtf16 empty ASCII Unicode and round-trip") {
  CHECK(ToUtf8(L"").empty());
  CHECK(ToUtf16("").empty());

  CHECK(ToUtf8(L"ABC xyz 012") == "ABC xyz 012");
  CHECK(ToUtf16("ABC xyz 012") == L"ABC xyz 012");

  const std::wstring e_acute_utf16 = L"\u00E9";
  const std::string e_acute_utf8 = kEAcuteUtf8;
  CHECK(ToUtf8(e_acute_utf16) == e_acute_utf8);
  CHECK(ToUtf16(e_acute_utf8) == e_acute_utf16);

  const std::string cafe_utf8 = std::string("caf") + kEAcuteUtf8;
  CHECK(ToUtf8(ToUtf16(cafe_utf8)) == cafe_utf8);
  CHECK(ToUtf16(ToUtf8(L"caf\u00E9")) == L"caf\u00E9");
  CHECK(ToUtf8(ToUtf16("plain ASCII")) == "plain ASCII");
  CHECK(ToUtf16(ToUtf8(L"plain ASCII")) == L"plain ASCII");
}

TEST_CASE("Trim empty already-trim and ASCII whitespace ends") {
  CHECK(Trim("").empty());
  CHECK(Trim("already-trim") == "already-trim");
  CHECK(Trim("internal space stays") == "internal space stays");

  CHECK(Trim("  hello  ") == "hello");
  CHECK(Trim("\thello\t") == "hello");
  CHECK(Trim("\rhello\r") == "hello");
  CHECK(Trim("\nhello\n") == "hello");
  CHECK(Trim("\fhello\f") == "hello");
  CHECK(Trim("\vhello\v") == "hello");
  CHECK(Trim(" \t\r\n\f\vcore\v\f\n\r\t ") == "core");
  CHECK(Trim(" \t\r\n\f\v").empty());
}

TEST_CASE("Split skips empty fields trims parts and handles separators") {
  const std::vector<std::string> skipped = Split("a,,b", ',');
  REQUIRE(skipped.size() == 2);
  CHECK(skipped[0] == "a");
  CHECK(skipped[1] == "b");

  const std::vector<std::string> trimmed = Split("  a  ,  b  ,  c  ", ',');
  REQUIRE(trimmed.size() == 3);
  CHECK(trimmed[0] == "a");
  CHECK(trimmed[1] == "b");
  CHECK(trimmed[2] == "c");

  const std::vector<std::string> no_separator = Split("only-part", ',');
  REQUIRE(no_separator.size() == 1);
  CHECK(no_separator[0] == "only-part");

  const std::vector<std::string> trailing = Split("a,b,", ',');
  REQUIRE(trailing.size() == 2);
  CHECK(trailing[0] == "a");
  CHECK(trailing[1] == "b");

  CHECK(Split("", ',').empty());
  CHECK(Split(",,,", ',').empty());
  CHECK(Split(",", ',').empty());
}

TEST_CASE("Join empty one and several parts") {
  const std::vector<std::string> none;
  CHECK(Join(none, ",").empty());

  const std::vector<std::string> one{"only"};
  CHECK(Join(one, ",") == "only");
  CHECK(Join(one, "") == "only");

  const std::vector<std::string> several{"a", "b", "c"};
  CHECK(Join(several, ",") == "a,b,c");
  CHECK(Join(several, "") == "abc");
  CHECK(Join(several, "::") == "a::b::c");
}

TEST_CASE("EqualsIgnoreCase and ToLowerAscii mixed empty and length") {
  CHECK(EqualsIgnoreCase("ABC", "abc"));
  CHECK(EqualsIgnoreCase("AbC-XyZ", "aBc-xYz"));
  CHECK(EqualsIgnoreCase("", ""));
  CHECK(EqualsIgnoreCase("same", "same"));

  CHECK_FALSE(EqualsIgnoreCase("abc", "abcd"));
  CHECK_FALSE(EqualsIgnoreCase("abcd", "abc"));
  CHECK_FALSE(EqualsIgnoreCase("", "a"));
  CHECK_FALSE(EqualsIgnoreCase("a", ""));
  CHECK_FALSE(EqualsIgnoreCase("abc", "abd"));

  CHECK(ToLowerAscii("ABC") == "abc");
  CHECK(ToLowerAscii("AbC123") == "abc123");
  CHECK(ToLowerAscii("already") == "already");
  CHECK(ToLowerAscii("").empty());
  CHECK(ToLowerAscii("MiXeD-ID") == "mixed-id");
}

TEST_CASE("ParseUnsigned decimal hex trim and failure modes") {
  std::uint64_t out = 99;

  REQUIRE(ParseUnsigned("42", out));
  CHECK(out == 42);

  REQUIRE(ParseUnsigned("0", out));
  CHECK(out == 0);

  REQUIRE(ParseUnsigned("0x10", out));
  CHECK(out == 0x10);

  REQUIRE(ParseUnsigned("0XFF", out));
  CHECK(out == 0xFF);

  REQUIRE(ParseUnsigned("0x0", out));
  CHECK(out == 0);

  REQUIRE(ParseUnsigned("  7  ", out));
  CHECK(out == 7);

  REQUIRE(ParseUnsigned("\t0x2a\n", out));
  CHECK(out == 0x2a);

  REQUIRE(ParseUnsigned("18446744073709551615", out));
  CHECK(out == (std::numeric_limits<std::uint64_t>::max)());

  REQUIRE(ParseUnsigned("0xffffffffffffffff", out));
  CHECK(out == (std::numeric_limits<std::uint64_t>::max)());

  out = 123;
  CHECK_FALSE(ParseUnsigned("", out));
  CHECK(out == 123);

  CHECK_FALSE(ParseUnsigned("   ", out));
  CHECK_FALSE(ParseUnsigned("0x", out));
  CHECK_FALSE(ParseUnsigned("0X", out));
  CHECK_FALSE(ParseUnsigned("18446744073709551616", out));
  CHECK_FALSE(ParseUnsigned("0x10000000000000000", out));
  CHECK_FALSE(ParseUnsigned("12!", out));
  CHECK_FALSE(ParseUnsigned("12a", out));
  CHECK_FALSE(ParseUnsigned("xyz", out));
  CHECK_FALSE(ParseUnsigned("0xg", out));
}

TEST_CASE("ParseGuid and FormatGuid string-order hex with no mixed-endian swap") {
  static_assert(kGuidOctets == 16);

  const std::array<std::uint8_t, kGuidOctets> expected = SampleGuidBytes();
  std::array<std::uint8_t, kGuidOctets> bytes{};

  REQUIRE(ParseGuid("{a1b2c3d4-e5f6-7890-abcd-ef0123456789}", bytes));
  CHECK(bytes == expected);
  CHECK(bytes[0] == 0xa1);
  CHECK(bytes[1] == 0xb2);
  CHECK(bytes[2] == 0xc3);
  CHECK(bytes[3] == 0xd4);

  bytes = {};
  REQUIRE(ParseGuid("a1b2c3d4-e5f6-7890-abcd-ef0123456789", bytes));
  CHECK(bytes == expected);

  bytes = {};
  REQUIRE(ParseGuid("A1B2C3D4E5F67890ABCDEF0123456789", bytes));
  CHECK(bytes == expected);

  bytes = {};
  REQUIRE(ParseGuid("  {a1b2c3d4-e5f6-7890-abcd-ef0123456789}  ", bytes));
  CHECK(bytes == expected);

  CHECK_FALSE(ParseGuid("a1b2c3d4", bytes));
  CHECK_FALSE(ParseGuid("{a1b2c3d4-e5f6-7890-abcd-ef012345678}", bytes));
  CHECK_FALSE(ParseGuid("{a1b2c3d4-e5f6-7890-abcd-ef012345678g}", bytes));
  CHECK_FALSE(ParseGuid("not-a-guid-value!!", bytes));
  CHECK_FALSE(ParseGuid("", bytes));
  CHECK_FALSE(ParseGuid("{}", bytes));

  CHECK(FormatGuid(expected) == "{a1b2c3d4-e5f6-7890-abcd-ef0123456789}");

  std::array<std::uint8_t, kGuidOctets> roundtrip{};
  REQUIRE(ParseGuid(FormatGuid(expected), roundtrip));
  CHECK(roundtrip == expected);
}
