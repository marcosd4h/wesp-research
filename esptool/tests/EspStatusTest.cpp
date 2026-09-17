#include <doctest.h>

#include "esp/EspStatus.h"

TEST_CASE("NtStatusToResult leaves error-mask statuses unchanged") {
  using esptool::esp::EspResult;
  using esptool::esp::NtStatusToResult;
  using esptool::esp::kNtStatusErrorMask;
  using esptool::esp::kStatusAccessViolation;

  CHECK(NtStatusToResult(0xC0000005u) ==
        static_cast<EspResult>(0xC0000005));
  CHECK(NtStatusToResult(0xC0000005u) == kStatusAccessViolation);
  CHECK(NtStatusToResult(kNtStatusErrorMask) ==
        static_cast<EspResult>(kNtStatusErrorMask));
}

TEST_CASE("NtStatusToResult stamps facility bits on success NTSTATUS 0") {
  using esptool::esp::EspResult;
  using esptool::esp::NtStatusToResult;

  constexpr EspResult kExpected = static_cast<EspResult>(
      0x10000000u | 0x20000000u | 0x40000000u);
  CHECK(NtStatusToResult(0) == kExpected);

  constexpr EspResult kStamped = static_cast<EspResult>(
      0x103u | 0x10000000u | 0x20000000u | 0x40000000u);
  CHECK(NtStatusToResult(0x103) == kStamped);
}

TEST_CASE("DescribeResult returns HRESULT for unknown codes") {
  using esptool::esp::DescribeResult;
  using esptool::esp::EspResult;

  CHECK(DescribeResult(static_cast<EspResult>(0x80004001)) == "HRESULT");
  CHECK(DescribeResult(1) == "HRESULT");
}

TEST_CASE("HexResult formats kInvalidArg as uppercase 8-digit hex") {
  using esptool::esp::HexResult;
  using esptool::esp::kInvalidArg;
  using esptool::esp::kOk;
  using esptool::esp::kStatusAccessViolation;

  CHECK(HexResult(kInvalidArg) == "0x80070057");
  CHECK(HexResult(kOk) == "0x00000000");
  CHECK(HexResult(kStatusAccessViolation) == "0xC0000005");
}
