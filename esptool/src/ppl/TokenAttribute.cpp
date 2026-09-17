// Token privilege and WESP://Permission stamp. PhntUser.h stays in this
// .cpp. TokenAttribute.h is this-tool constants only, no PHNT.

#include "ppl/TokenAttribute.h"

#include <array>
#include <cstring>
#include <format>
#include <ranges>
#include <span>
#include <string>
#include <string_view>
#include <vector>

#include "esp/PhntUser.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool::ppl {
namespace {

constexpr std::size_t kOctetStringBytes = 16;
constexpr unsigned kOctetTagDword = 1;
constexpr std::size_t kOctetTagBytes = 4;
constexpr std::size_t kOctetPermissionOffset = 4;
constexpr std::size_t kQueryBufferSlop = 64;
static_assert(kOctetStringBytes == 16);
static_assert(kOctetPermissionOffset == kOctetTagBytes);
static_assert(kOctetTagDword == 1);

// Handwritten GetProcAddress aliases. Do not decltype(&NtSetInformationToken)
// (static import).
using NtSetInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE,
                                                 TOKEN_INFORMATION_CLASS, PVOID,
                                                 ULONG);
using NtQueryInformationTokenFn = NTSTATUS(NTAPI*)(HANDLE,
                                                   TOKEN_INFORMATION_CLASS,
                                                   PVOID, ULONG, PULONG);

[[nodiscard]] std::string StatusHex(NTSTATUS status) {
  return std::format("0x{:08X}", static_cast<unsigned>(status));
}

using text::Win32Message;

[[nodiscard]] NtSetInformationTokenFn SetFn() {
  static const NtSetInformationTokenFn fn =
      NtdllProc<NtSetInformationTokenFn>("NtSetInformationToken");
  return fn;
}

[[nodiscard]] NtQueryInformationTokenFn QueryFn() {
  static const NtQueryInformationTokenFn fn =
      NtdllProc<NtQueryInformationTokenFn>("NtQueryInformationToken");
  return fn;
}

[[nodiscard]] bool ReadTokenInfo(HANDLE token, TOKEN_INFORMATION_CLASS info,
                                 std::vector<std::byte>& buffer) {
  DWORD needed = 0;
  GetTokenInformation(token, info, nullptr, 0, &needed);
  if (needed == 0) {
    return false;
  }
  buffer.resize(needed);
  return GetTokenInformation(token, info, buffer.data(), needed, &needed) !=
         FALSE;
}

[[nodiscard]] UNICODE_STRING MakeName(
    std::array<wchar_t, std::size(kWespPermissionAttributeName)>& storage) {
  std::ranges::copy(kWespPermissionAttributeName, storage.begin());
  UNICODE_STRING name{};
  name.Length = static_cast<USHORT>((storage.size() - 1) * sizeof(wchar_t));
  name.MaximumLength = name.Length;
  name.Buffer = storage.data();
  return name;
}

[[nodiscard]] NTSTATUS ApplyOperation(
    HANDLE token, unsigned permission,
    TOKEN_SECURITY_ATTRIBUTE_OPERATION operation) {
  NtSetInformationTokenFn set = SetFn();
  if (set == nullptr) {
    return STATUS_ENTRYPOINT_NOT_FOUND;
  }

  // 16-byte OCTET_STRING: little-endian tag dword 1, then the permission
  // dword. The tag bytes stay a literal so the on-wire layout cannot depend
  // on the host integer width of `unsigned`.
  constexpr std::array<std::byte, kOctetTagBytes> kOctetTag{
      std::byte{1}, std::byte{0}, std::byte{0}, std::byte{0}};
  std::array<std::byte, kOctetStringBytes> payload{};
  std::memcpy(payload.data(), kOctetTag.data(), kOctetTag.size());
  std::memcpy(payload.data() + kOctetPermissionOffset, &permission,
              sizeof(permission));

  TOKEN_SECURITY_ATTRIBUTE_OCTET_STRING_VALUE value{};
  value.Value = payload.data();
  value.ValueLength = static_cast<ULONG>(payload.size());

  std::array<wchar_t, std::size(kWespPermissionAttributeName)> name_storage{};
  TOKEN_SECURITY_ATTRIBUTE_V1 attr{};
  attr.Name = MakeName(name_storage);
  attr.ValueType = TOKEN_SECURITY_ATTRIBUTE_TYPE_OCTET_STRING;
  attr.Flags = TOKEN_SECURITY_ATTRIBUTE_MANDATORY;
  attr.ValueCount = 1;
  attr.Values.OctetString = &value;

  TOKEN_SECURITY_ATTRIBUTES_INFORMATION info{};
  info.Version = TOKEN_SECURITY_ATTRIBUTES_INFORMATION_VERSION_V1;
  info.AttributeCount = 1;
  info.AttributeV1 = &attr;

  TOKEN_SECURITY_ATTRIBUTE_OPERATION op = operation;
  TOKEN_SECURITY_ATTRIBUTES_AND_OPERATION_INFORMATION set_info{};
  set_info.Attributes = &info;
  set_info.Operations = &op;
  return set(token, TokenSecurityAttributes, &set_info, sizeof(set_info));
}

}  // namespace

UniqueHandle OpenCurrentToken(DWORD access) {
  HANDLE raw = nullptr;
  if (!OpenProcessToken(GetCurrentProcess(), access, &raw)) {
    return {};
  }
  return UniqueHandle(raw);
}

std::string TokenAttributeState::Describe() const {
  if (!queried) {
    return "not queried";
  }
  if (!present) {
    return std::format("absent (query {})", StatusHex(query_status));
  }
  if (permission == kWespPermissionFull) {
    return std::format("present full ({})", permission);
  }
  if (permission == kWespPermissionRestricted) {
    return std::format("present restricted ({})", permission);
  }
  return std::format("present value={}", permission);
}

bool EnablePrivilege(std::wstring_view name, std::string& error) {
  error.clear();
  UniqueHandle token = OpenCurrentToken(TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY);
  if (!token) {
    error = Win32Message("OpenProcessToken failed", GetLastError());
    return false;
  }
  const std::wstring owned(name);
  LUID luid{};
  if (!LookupPrivilegeValueW(nullptr, owned.c_str(), &luid)) {
    error = Win32Message("LookupPrivilegeValue failed", GetLastError());
    return false;
  }
  TOKEN_PRIVILEGES privileges{};
  privileges.PrivilegeCount = 1;
  privileges.Privileges[0].Luid = luid;
  privileges.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
  const BOOL adjusted = AdjustTokenPrivileges(
      token.get(), FALSE, &privileges, sizeof(privileges), nullptr, nullptr);
  const DWORD failure = GetLastError();
  if (adjusted == FALSE || failure == ERROR_NOT_ALL_ASSIGNED) {
    error = Win32Message("AdjustTokenPrivileges failed", failure);
    return false;
  }
  return true;
}

PrivilegeState QueryPrivilege(std::wstring_view name) {
  PrivilegeState state;
  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY);
  if (!token) {
    return state;
  }
  const std::wstring owned(name);
  LUID luid{};
  if (!LookupPrivilegeValueW(nullptr, owned.c_str(), &luid)) {
    return state;
  }
  std::vector<std::byte> buffer;
  if (!ReadTokenInfo(token.get(), TokenPrivileges, buffer)) {
    return state;
  }

  const auto* privileges = reinterpret_cast<TOKEN_PRIVILEGES*>(buffer.data());
  for (DWORD index = 0; index < privileges->PrivilegeCount; ++index) {
    const LUID_AND_ATTRIBUTES& entry = privileges->Privileges[index];
    if (entry.Luid.LowPart == luid.LowPart &&
        entry.Luid.HighPart == luid.HighPart) {
      state.present = true;
      state.enabled = (entry.Attributes & SE_PRIVILEGE_ENABLED) != 0;
      return state;
    }
  }
  return state;
}

bool RequireSystemWithTcb(std::string& error) {
  error.clear();
  if (!IsSystemAccount()) {
    error = "this command requires a process launched as NT AUTHORITY\\SYSTEM";
    return false;
  }
  if (!QueryPrivilege(SE_TCB_NAME).present) {
    error = "this command requires SeTcbPrivilege on the process token";
    return false;
  }
  if (!EnablePrivilege(SE_TCB_NAME, error)) {
    error = std::format(
        "SeTcbPrivilege is present but could not be enabled: {}", error);
    return false;
  }
  return true;
}

bool IsSystemAccount() {
  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY);
  if (!token) {
    return false;
  }
  std::vector<std::byte> buffer;
  if (!ReadTokenInfo(token.get(), TokenUser, buffer)) {
    return false;
  }

  std::array<std::byte, SECURITY_MAX_SID_SIZE> system_sid{};
  DWORD sid_size = static_cast<DWORD>(system_sid.size());
  auto* sid = reinterpret_cast<PSID>(system_sid.data());
  if (!CreateWellKnownSid(WinLocalSystemSid, nullptr, sid, &sid_size)) {
    return false;
  }
  const auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
  return EqualSid(user->User.Sid, sid) != FALSE;
}

bool SetWespPermission(unsigned permission, std::string& error) {
  error.clear();
  std::string privilege_error;
  const bool have_tcb = EnablePrivilege(SE_TCB_NAME, privilege_error);

  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT);
  if (!token) {
    error = Win32Message("OpenProcessToken failed", GetLastError());
    return false;
  }

  // EnablePrivilege is best-effort. ADD first; REPLACE only if ADD fails.
  // A TCB failure is appended to the NtSet error, not returned alone.
  NTSTATUS status = ApplyOperation(token.get(), permission,
                                   TOKEN_SECURITY_ATTRIBUTE_OPERATION_ADD);
  if (!NT_SUCCESS(status)) {
    status = ApplyOperation(token.get(), permission,
                            TOKEN_SECURITY_ATTRIBUTE_OPERATION_REPLACE);
  }
  if (!NT_SUCCESS(status)) {
    error = std::format("NtSetInformationToken failed {}", StatusHex(status));
    if (!have_tcb && !privilege_error.empty()) {
      error += std::format(" ({})", privilege_error);
    }
    return false;
  }
  TokenAttributeState verified;
  std::string query_error;
  if (!QueryWespPermission(verified, query_error) || !verified.present ||
      verified.permission != permission) {
    error = std::format("NtSetInformationToken succeeded but {} is {}",
                        kWespPermissionClaim, verified.Describe());
    if (!query_error.empty()) {
      error += std::format(" ({})", query_error);
    }
    return false;
  }
  return true;
}

bool DeleteWespPermission(std::string& error) {
  error.clear();
  std::string privilege_error;
  const bool have_tcb = EnablePrivilege(SE_TCB_NAME, privilege_error);

  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY | TOKEN_ADJUST_DEFAULT);
  if (!token) {
    error = Win32Message("OpenProcessToken failed", GetLastError());
    return false;
  }
  // DELETE still writes the 16-byte payload. The permission dword is
  // kWespPermissionFull; this is not a "delete only if Full" check.
  const NTSTATUS status =
      ApplyOperation(token.get(), kWespPermissionFull,
                     TOKEN_SECURITY_ATTRIBUTE_OPERATION_DELETE);
  if (!NT_SUCCESS(status)) {
    error = std::format("NtSetInformationToken(DELETE) failed {}",
                        StatusHex(status));
    if (!have_tcb && !privilege_error.empty()) {
      error += std::format(" ({})", privilege_error);
    }
    return false;
  }

  TokenAttributeState verified;
  std::string query_error;
  if (!QueryWespPermission(verified, query_error)) {
    error = std::format(
        "NtSetInformationToken(DELETE) succeeded but failed to re-query {}: {}",
        kWespPermissionClaim, query_error);
    return false;
  }
  if (verified.present) {
    error = std::format(
        "NtSetInformationToken(DELETE) succeeded but {} is still present: {}",
        kWespPermissionClaim, verified.Describe());
    return false;
  }
  return true;
}

bool QueryWespPermission(TokenAttributeState& out, std::string& error) {
  error.clear();
  out = TokenAttributeState{};
  NtQueryInformationTokenFn query = QueryFn();
  if (query == nullptr) {
    error = "NtQueryInformationToken is not available";
    return false;
  }

  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY);
  if (!token) {
    error = Win32Message("OpenProcessToken failed", GetLastError());
    return false;
  }

  ULONG needed = 0;
  NTSTATUS status =
      query(token.get(), TokenSecurityAttributes, nullptr, 0, &needed);
  out.query_status = status;
  if (needed == 0) {
    out.queried = true;
    error = std::format("NtQueryInformationToken size probe failed {}",
                        StatusHex(status));
    return false;
  }

  std::vector<std::byte> buffer(static_cast<std::size_t>(needed) +
                                kQueryBufferSlop);
  ULONG got = 0;
  status = query(token.get(), TokenSecurityAttributes, buffer.data(),
                 static_cast<ULONG>(buffer.size()), &got);
  out.query_status = status;
  out.queried = true;
  if (!NT_SUCCESS(status)) {
    error = std::format("NtQueryInformationToken failed {}", StatusHex(status));
    return false;
  }

  return DecodeWespPermissionBlob(
      std::as_bytes(std::span(buffer.data(), static_cast<std::size_t>(got))),
      out);
}

bool DecodeWespPermissionBlob(std::span<const std::byte> data,
                              TokenAttributeState& out) {
  out.present = false;
  out.permission = 0;
  if (data.empty()) {
    return true;
  }

  const std::size_t name_bytes =
      wcslen(kWespPermissionAttributeName) * sizeof(wchar_t);
  if (data.size() < name_bytes) {
    return true;
  }
  std::size_t name_offset = 0;
  bool name_found = false;
  for (std::size_t offset = 0; offset + name_bytes <= data.size(); ++offset) {
    if (std::memcmp(data.data() + offset, kWespPermissionAttributeName,
                    name_bytes) == 0) {
      name_found = true;
      name_offset = offset;
      break;
    }
  }
  if (!name_found) {
    return true;
  }
  out.present = true;

  // Inclusive last window: offset + 16 <= size. Walk starts at the claim
  // name. `offset < size - 16` drops a payload that begins at size-16
  // (live got=216, OCTET at 200).
  for (std::size_t offset = name_offset;
       offset + kOctetStringBytes <= data.size(); ++offset) {
    unsigned tag = 0;
    unsigned permission = 0;
    std::memcpy(&tag, data.data() + offset, sizeof(tag));
    std::memcpy(&permission, data.data() + offset + kOctetPermissionOffset,
                sizeof(permission));
    if (tag == kOctetTagDword) {
      out.permission = permission;
      return true;
    }
  }
  return true;
}

}  // namespace esptool::ppl
