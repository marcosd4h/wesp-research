#pragma once

#include <cstdint>
#include <string>

namespace esptool::ppl {

// Decoded PS_PROTECTION value for a process.
struct ProtectionState {
  bool queried = false;
  long query_status = 0;
  std::uint8_t level = 0;
  std::uint8_t type = 0;
  std::uint8_t audit = 0;
  std::uint8_t signer = 0;

  [[nodiscard]] bool IsProtectedLight() const noexcept { return type == 1; }
  // 0x31 == PsProtectedValue(Antimalware, FALSE, ProtectedLight). Asserted in
  // Protection.cpp.
  [[nodiscard]] bool IsAntimalwareLight() const noexcept {
    return level == 0x31;
  }
  [[nodiscard]] std::string Describe() const;
};

// Queries the protection state of the current process and of an arbitrary
// process identifier. Returns a zeroed state when the query fails.
[[nodiscard]] ProtectionState QueryCurrentProcess();
[[nodiscard]] ProtectionState QueryProcess(unsigned long process_id);

// Returns true when the process token can elevate.
[[nodiscard]] bool IsElevated();

// SystemCodeIntegrityInformation (class 0x67). Bit 0x2 is test signing.
struct CodeIntegrityState {
  bool queried = false;
  unsigned options = 0;
  long query_status = 0;

  // CODEINTEGRITY_OPTION_TESTSIGN / _ENABLED. Named macros stay in
  // Protection.cpp.
  [[nodiscard]] bool TestSigning() const noexcept {
    return (options & 0x2u) != 0;
  }
  [[nodiscard]] bool IntegrityEnabled() const noexcept {
    return (options & 0x1u) != 0;
  }
  [[nodiscard]] std::string Describe() const;
};

[[nodiscard]] CodeIntegrityState QueryCodeIntegrity();

// HKLM Secure Boot state. queried is false when the firmware key is absent.
struct SecureBootState {
  bool queried = false;
  bool enabled = false;
  std::string error;
};

[[nodiscard]] SecureBootState QuerySecureBootEnabled();

}  // namespace esptool::ppl
