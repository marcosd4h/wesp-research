#include <doctest.h>
#include "ppl/TokenAttribute.h"

#include <Windows.h>

#include <cstddef>
#include <cstring>
#include <span>
#include <string>
#include <string_view>
#include <vector>

using esptool::ppl::DecodeWespPermissionBlob;
using esptool::ppl::EnablePrivilege;
using esptool::ppl::IsSystemAccount;
using esptool::ppl::PrivilegeState;
using esptool::ppl::QueryPrivilege;
using esptool::ppl::QueryWespPermission;
using esptool::ppl::RequireSystemWithTcb;
using esptool::ppl::TokenAttributeState;
using esptool::ppl::kWespPermissionAttributeName;
using esptool::ppl::kWespPermissionFull;
using esptool::ppl::kWespPermissionRestricted;

namespace {

constexpr unsigned kOctetTag = 1;
constexpr unsigned kOtherOctetTag = 2;
constexpr unsigned kUnknownPermission = 42;
constexpr std::size_t kOctetBytes = 16;
constexpr std::size_t kNameChars =
    sizeof(kWespPermissionAttributeName) / sizeof(wchar_t) - 1;

[[nodiscard]] bool Contains(std::string_view text, std::string_view needle) {
  return text.find(needle) != std::string_view::npos;
}

[[nodiscard]] std::vector<std::byte> ClaimNameBytes() {
  const std::span<const wchar_t> chars(kWespPermissionAttributeName, kNameChars);
  const std::span<const std::byte> bytes = std::as_bytes(chars);
  return {bytes.begin(), bytes.end()};
}

void AppendLeU32(std::vector<std::byte>& blob, unsigned value) {
  const std::size_t at = blob.size();
  blob.resize(at + sizeof(value));
  std::memcpy(blob.data() + at, &value, sizeof(value));
}

void AppendOctetWindow(std::vector<std::byte>& blob, unsigned tag,
                       unsigned permission) {
  AppendLeU32(blob, tag);
  AppendLeU32(blob, permission);
  blob.insert(blob.end(), kOctetBytes - 8, std::byte{0});
}

[[nodiscard]] TokenAttributeState MustDecode(std::span<const std::byte> data) {
  TokenAttributeState out;
  REQUIRE(DecodeWespPermissionBlob(data, out));
  return out;
}

}  // namespace

TEST_CASE("DecodeWespPermissionBlob empty span is absent with permission 0") {
  const TokenAttributeState out = MustDecode({});
  CHECK_FALSE(out.present);
  CHECK(out.permission == 0);
}

TEST_CASE("DecodeWespPermissionBlob blob shorter than the claim name is absent") {
  auto blob = ClaimNameBytes();
  REQUIRE(blob.size() > 0);
  blob.pop_back();
  const TokenAttributeState out = MustDecode(blob);
  CHECK_FALSE(out.present);
  CHECK(out.permission == 0);
}

TEST_CASE(
    "DecodeWespPermissionBlob name without a tag-1 window is present with "
    "permission 0") {
  auto blob = ClaimNameBytes();
  blob.insert(blob.end(), 20, std::byte{0xAA});
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == 0);
}

TEST_CASE("DecodeWespPermissionBlob reads restricted permission after the name") {
  auto blob = ClaimNameBytes();
  blob.insert(blob.end(), 5, std::byte{0xCC});
  AppendOctetWindow(blob, kOctetTag, kWespPermissionRestricted);
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == kWespPermissionRestricted);
}

TEST_CASE("DecodeWespPermissionBlob reads full permission after the name") {
  auto blob = ClaimNameBytes();
  blob.insert(blob.end(), 5, std::byte{0xCC});
  AppendOctetWindow(blob, kOctetTag, kWespPermissionFull);
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == kWespPermissionFull);
}

TEST_CASE("DecodeWespPermissionBlob keeps an unknown permission after tag 1") {
  auto blob = ClaimNameBytes();
  AppendOctetWindow(blob, kOctetTag, kUnknownPermission);
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == kUnknownPermission);
}

TEST_CASE(
    "DecodeWespPermissionBlob accepts a tag-1 window that starts at size-16") {
  auto blob = ClaimNameBytes();
  const std::size_t window_at = blob.size();
  AppendOctetWindow(blob, kOctetTag, kWespPermissionRestricted);
  REQUIRE(blob.size() >= kOctetBytes);
  CHECK(window_at == blob.size() - kOctetBytes);
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == kWespPermissionRestricted);
}

TEST_CASE(
    "DecodeWespPermissionBlob skips a non-1 tag until a later tag-1 window") {
  auto blob = ClaimNameBytes();
  AppendOctetWindow(blob, kOtherOctetTag, kWespPermissionFull);
  AppendOctetWindow(blob, kOctetTag, kWespPermissionRestricted);
  const TokenAttributeState out = MustDecode(blob);
  CHECK(out.present);
  CHECK(out.permission == kWespPermissionRestricted);
}

TEST_CASE("QueryPrivilege SE_CHANGE_NOTIFY_NAME matches the current token") {
  const PrivilegeState state = QueryPrivilege(SE_CHANGE_NOTIFY_NAME);

  HANDLE raw = nullptr;
  REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw));
  const esptool::UniqueHandle token(raw);

  LUID luid{};
  const BOOL looked_up =
      LookupPrivilegeValueW(nullptr, SE_CHANGE_NOTIFY_NAME, &luid);

  bool found_in_token = false;
  DWORD attrs = 0;
  if (looked_up != FALSE) {
    DWORD needed = 0;
    GetTokenInformation(token.get(), TokenPrivileges, nullptr, 0, &needed);
    REQUIRE(needed > 0);
    std::vector<std::byte> buffer(needed);
    REQUIRE(GetTokenInformation(token.get(), TokenPrivileges, buffer.data(),
                                needed, &needed) != FALSE);
    const auto* privileges =
        reinterpret_cast<const TOKEN_PRIVILEGES*>(buffer.data());
    for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
      const LUID_AND_ATTRIBUTES& entry = privileges->Privileges[index];
      if (entry.Luid.LowPart == luid.LowPart &&
          entry.Luid.HighPart == luid.HighPart) {
        found_in_token = true;
        attrs = entry.Attributes;
        break;
      }
    }
  }

  CHECK(state.present == found_in_token);
  if (found_in_token) {
    const bool enabled_in_token = (attrs & SE_PRIVILEGE_ENABLED) != 0;
    CHECK(state.enabled == enabled_in_token);
  }
}

TEST_CASE("QueryWespPermission sets queried or a nonempty error") {
  TokenAttributeState state;
  std::string error;
  const bool ok = QueryWespPermission(state, error);
  if (ok) {
    CHECK(state.queried);
    CHECK(error.empty());
  } else if (error.find("NtQueryInformationToken") == 0) {
    CHECK(error.find("NtQueryInformationToken") == 0);
  } else {
    CHECK(error.find("OpenProcessToken failed") == 0);
  }
}

TEST_CASE("RequireSystemWithTcb fails without SYSTEM and checks TCB when SYSTEM") {
  std::string error;
  if (!IsSystemAccount()) {
    CHECK_FALSE(RequireSystemWithTcb(error));
    const bool mentions_system = Contains(error, "SYSTEM");
    CHECK(mentions_system);
    CHECK(error ==
          "this command requires a process launched as NT AUTHORITY\\SYSTEM");
  } else {
    const PrivilegeState tcb = QueryPrivilege(SE_TCB_NAME);
    const bool ok = RequireSystemWithTcb(error);
    if (tcb.present) {
      if (!ok) {
        const bool mentions_tcb = Contains(error, "SeTcbPrivilege");
        CHECK(mentions_tcb);
      } else {
        CHECK(error.empty());
      }
    } else {
      CHECK_FALSE(ok);
      const bool mentions_tcb = Contains(error, "SeTcbPrivilege");
      CHECK(mentions_tcb);
    }
  }
}

TEST_CASE("EnablePrivilege rejects a nonsense privilege name") {
  std::string error;
  CHECK_FALSE(EnablePrivilege(L"SeNotARealPrivilegeNameForEsptool", error));
  CHECK(error.find("LookupPrivilegeValue failed") == 0);
}
