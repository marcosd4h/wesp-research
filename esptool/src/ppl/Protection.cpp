// PS_PROTECTION / CI. PhntUser.h stays in this .cpp, not Protection.h.

#include "ppl/Protection.h"

#include "esp/PhntUser.h"

#include <format>

#include "ppl/TokenAttribute.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"
#include "util/UniqueWin.h"

namespace esptool::ppl {
namespace {

using NtQueryInformationProcessFn = NTSTATUS(NTAPI*)(HANDLE, PROCESSINFOCLASS,
                                                     PVOID, ULONG, PULONG);
using NtQuerySystemInformationFn = NTSTATUS(NTAPI*)(SYSTEM_INFORMATION_CLASS,
                                                    PVOID, ULONG, PULONG);

// Pin header predicates (0x31, CI 0x1/0x2, classes 61/103) to PHNT names. Keep
// PHNT out of Protection.h.
static_assert(PsProtectedValue(PsProtectedSignerAntimalware, FALSE,
                               PsProtectedTypeProtectedLight) == 0x31);
static_assert(CODEINTEGRITY_OPTION_ENABLED == 0x01);
static_assert(CODEINTEGRITY_OPTION_TESTSIGN == 0x02);
static_assert(ProcessProtectionInformation == 61);
static_assert(SystemCodeIntegrityInformation == 103);

[[nodiscard]] bool QueryRaw(HANDLE process, std::uint8_t& out,
                            NTSTATUS& out_status) {
  out_status = 0;
  static const NtQueryInformationProcessFn query =
      NtdllProc<NtQueryInformationProcessFn>("NtQueryInformationProcess");
  if (query == nullptr) {
    out_status = static_cast<NTSTATUS>(0xC0000225L);  // STATUS_NOT_FOUND
    return false;
  }
  PS_PROTECTION protection{};
  ULONG returned = 0;
  const NTSTATUS status = query(process, ProcessProtectionInformation,
                                &protection, sizeof(protection), &returned);
  out_status = status;
  if (!NT_SUCCESS(status)) {
    return false;
  }
  out = protection.Level;
  return true;
}

[[nodiscard]] ProtectionState Decode(std::uint8_t raw, long status) {
  ProtectionState state;
  state.queried = true;
  state.query_status = status;
  state.level = raw;
  state.type = static_cast<std::uint8_t>(raw & PS_PROTECTED_TYPE_MASK);
  state.audit = static_cast<std::uint8_t>((raw & PS_PROTECTED_AUDIT_MASK) != 0);
  state.signer = static_cast<std::uint8_t>((raw >> 4) & 0x0Fu);
  return state;
}

using text::Win32Message;

}  // namespace

std::string ProtectionState::Describe() const {
  const char* type_name = type == 0   ? "None"
                          : type == 1 ? "ProtectedLight"
                                      : "Protected";
  const char* signer_name = "Unknown";
  switch (signer) {
    case 0:
      signer_name = "None";
      break;
    case 1:
      signer_name = "Authenticode";
      break;
    case 2:
      signer_name = "CodeGen";
      break;
    case 3:
      signer_name = "Antimalware";
      break;
    case 4:
      signer_name = "Lsa";
      break;
    case 5:
      signer_name = "Windows";
      break;
    case 6:
      signer_name = "WinTcb";
      break;
    case 7:
      signer_name = "WinSystem";
      break;
    case 8:
      signer_name = "App";
      break;
    default:
      break;
  }
  return std::format("0x{:02X} ({}, {}, audit={})", level, signer_name,
                     type_name, static_cast<unsigned>(audit));
}

ProtectionState QueryCurrentProcess() {
  std::uint8_t raw = 0;
  NTSTATUS status = 0;
  if (QueryRaw(GetCurrentProcess(), raw, status)) {
    return Decode(raw, status);
  }
  ProtectionState failed;
  failed.queried = true;
  failed.query_status = status;
  return failed;
}

ProtectionState QueryProcess(unsigned long process_id) {
  UniqueHandle process(
      OpenProcess(PROCESS_QUERY_LIMITED_INFORMATION, FALSE, process_id));
  if (!process) {
    ProtectionState failed;
    failed.queried = true;
    failed.query_status = static_cast<NTSTATUS>(0xC0000022L);  // ACCESS_DENIED
    return failed;
  }
  std::uint8_t raw = 0;
  NTSTATUS status = 0;
  if (QueryRaw(process.get(), raw, status)) {
    return Decode(raw, status);
  }
  ProtectionState failed;
  failed.queried = true;
  failed.query_status = status;
  return failed;
}

bool IsElevated() {
  UniqueHandle token = OpenCurrentToken(TOKEN_QUERY);
  if (!token) {
    return false;
  }
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  const BOOL ok = GetTokenInformation(token.get(), TokenElevation, &elevation,
                                      sizeof(elevation), &returned);
  return ok != FALSE && elevation.TokenIsElevated != 0;
}

std::string CodeIntegrityState::Describe() const {
  if (!queried) {
    return "not queried";
  }
  return std::format("options=0x{:08X} testsigning={} ci={}", options,
                     TestSigning() ? "on" : "off",
                     IntegrityEnabled() ? "on" : "off");
}

CodeIntegrityState QueryCodeIntegrity() {
  static const NtQuerySystemInformationFn query =
      NtdllProc<NtQuerySystemInformationFn>("NtQuerySystemInformation");

  CodeIntegrityState state;
  if (query == nullptr) {
    return state;
  }
  SYSTEM_CODEINTEGRITY_INFORMATION info{};
  info.Length = sizeof(info);
  ULONG returned = 0;
  const NTSTATUS status =
      query(SystemCodeIntegrityInformation, &info, sizeof(info), &returned);
  state.queried = true;
  state.query_status = status;
  if (NT_SUCCESS(status)) {
    // Copy CodeIntegrityOptions. Do not read the unnamed bitfield union under
    // /permissive-.
    state.options = info.CodeIntegrityOptions;
  }
  return state;
}

SecureBootState QuerySecureBootEnabled() {
  SecureBootState state;
  HKEY raw = nullptr;
  const LSTATUS opened =
      RegOpenKeyExW(HKEY_LOCAL_MACHINE,
                    L"SYSTEM\\CurrentControlSet\\Control\\SecureBoot\\State", 0,
                    KEY_QUERY_VALUE, &raw);
  if (opened != ERROR_SUCCESS) {
    state.error =
        Win32Message("Secure Boot key is absent", static_cast<DWORD>(opened));
    return state;
  }
  UniqueRegKey key(raw);
  DWORD value = 0;
  DWORD size = sizeof(value);
  DWORD type = 0;
  const LSTATUS queried =
      RegQueryValueExW(key.get(), L"UEFISecureBootEnabled", nullptr, &type,
                       reinterpret_cast<LPBYTE>(&value), &size);
  if (queried != ERROR_SUCCESS) {
    state.error = Win32Message("UEFISecureBootEnabled is absent",
                               static_cast<DWORD>(queried));
    return state;
  }
  state.queried = true;
  state.enabled = value != 0;
  return state;
}

}  // namespace esptool::ppl
