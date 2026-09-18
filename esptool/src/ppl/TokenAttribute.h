#pragma once

#include <cstddef>
#include <span>
#include <string>
#include <string_view>

#include "util/UniqueHandle.h"

namespace esptool::ppl {

// Permission values decoded by wesp.sys. Full trust also requires the process
// to be Antimalware Protected Light. Restricted trust is accepted without
// that protection check. Live ground truth (VM_120, wesp!connect::setup):
// cmp rbx,2 then cmp ebx,1; neither 1000000000 nor 10000000 occurs anywhere
// in the binary. Stamping the old literals fails with 0x80070057.
constexpr unsigned kWespPermissionFull = 2u;
constexpr unsigned kWespPermissionRestricted = 1u;
// Connect-tier reserved discriminator. Full 32-bit discriminator DWORD
// 0x4D564900 (bytes MVI\0) is rejected with STATUS_ACCESS_DENIED before a
// session is created. Live disassembly shows cmp dword ptr [rsp+60h],4D564900h;
// 0xABCD occurs nowhere in the binary. Applies to the restricted tier only,
// checked against the connect-context discriminator DWORD (opcode-3 GUID.Data1).
constexpr unsigned kWespPermissionAbcdDeny = 0x4D564900u;
static_assert(kWespPermissionFull == 2u, "live connect compares permission to 2");
static_assert(kWespPermissionRestricted == 1u,
              "live connect compares permission to 1");
static_assert(kWespPermissionAbcdDeny == 0x4D564900u,
              "live connect compares discriminator to 0x4D564900");

inline constexpr wchar_t kWespPermissionAttributeName[] = L"WESP://Permission";
inline constexpr char kWespPermissionClaim[] = "WESP://Permission";

// Snapshot of the WESP://Permission record on the current process token.
struct TokenAttributeState {
  bool queried = false;
  bool present = false;
  unsigned permission = 0;
  long query_status = 0;

  [[nodiscard]] std::string Describe() const;
};

// Decodes one NtQueryInformationToken(TokenSecurityAttributes) blob.
// `out.present` is set when the claim name exists in the blob. `out.permission`
// is set when a 16-byte window at or after the name has tag dword 1 and a
// documented permission. The last legal window starts at size-16
// (`offset + 16 <= size`).
[[nodiscard]] bool DecodeWespPermissionBlob(std::span<const std::byte> data,
                                            TokenAttributeState& out);

struct PrivilegeState {
  bool present = false;
  bool enabled = false;
};

// Enables a privilege on the current process token. Returns false when the
// privilege is absent or AdjustTokenPrivileges fails.
[[nodiscard]] bool EnablePrivilege(std::wstring_view name, std::string& error);

// Present/enabled snapshot of a named privilege on the current primary token.
[[nodiscard]] PrivilegeState QueryPrivilege(std::wstring_view name);

// True when the current process token is NT AUTHORITY\SYSTEM.
[[nodiscard]] bool IsSystemAccount();

// Prerequisite for stamping WESP://Permission: the process must already be
// NT AUTHORITY\SYSTEM and must hold SeTcbPrivilege. This function enables TCB
// when it is present. It does not launch a child or spawn another binary.
[[nodiscard]] bool RequireSystemWithTcb(std::string& error);

// Adds or replaces WESP://Permission on the current primary token.
// Requires TOKEN_ADJUST_DEFAULT and SeTcbPrivilege (held by SYSTEM).
[[nodiscard]] bool SetWespPermission(unsigned permission, std::string& error);

// Removes the named WESP://Permission record when it is present.
[[nodiscard]] bool DeleteWespPermission(std::string& error);

// Reads the current primary token and reports whether WESP://Permission exists.
[[nodiscard]] bool QueryWespPermission(TokenAttributeState& out,
                                       std::string& error);

// OpenProcessToken on the current process. Empty when the open fails.
[[nodiscard]] UniqueHandle OpenCurrentToken(DWORD access);

}  // namespace esptool::ppl
