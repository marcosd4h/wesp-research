#pragma once

#include <cstdint>
#include <string>

#include "esp/EspTypes.h"

namespace esptool::esp {

// HRESULT success and failure predicates.
[[nodiscard]] constexpr bool Succeeded(EspResult result) noexcept {
  return result >= 0;
}

[[nodiscard]] constexpr bool Failed(EspResult result) noexcept {
  return result < 0;
}

// Converts an NTSTATUS value to the corresponding HRESULT.
[[nodiscard]] constexpr EspResult NtStatusToResult(
    std::uint32_t status) noexcept {
  if (status >= kNtStatusErrorMask) {
    return static_cast<EspResult>(status);
  }
  constexpr std::uint32_t kFacilityNtBit = 0x10000000u;
  constexpr std::uint32_t kSeverityCustomer = 0x20000000u;
  constexpr std::uint32_t kHresultSeverityError = 0x40000000u;
  return static_cast<EspResult>(status | kFacilityNtBit | kSeverityCustomer |
                                kHresultSeverityError);
}

// Human-readable name for the HRESULT values the client library returns.
[[nodiscard]] std::string DescribeResult(EspResult result);

// Compact hex form, for example "0x80070057".
[[nodiscard]] std::string HexResult(EspResult result);

}  // namespace esptool::esp
