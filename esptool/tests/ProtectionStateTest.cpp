#include <Windows.h>
#include <doctest.h>

#include <string>

#include "ppl/Protection.h"

using esptool::ppl::IsElevated;
using esptool::ppl::ProtectionState;
using esptool::ppl::QueryCurrentProcess;
using esptool::ppl::QueryProcess;
using esptool::ppl::QuerySecureBootEnabled;
using esptool::ppl::SecureBootState;

TEST_CASE("ProtectionState type 2 is Protected not ProtectedLight") {
  ProtectionState state;
  state.type = 2;
  CHECK(state.Describe() == "0x00 (None, Protected, audit=0)");
}

TEST_CASE("QueryCurrentProcess matches QueryProcess of GetCurrentProcessId") {
  const ProtectionState current = QueryCurrentProcess();
  CHECK(current.queried);
  CHECK(current.query_status >= 0);
  const ProtectionState by_id = QueryProcess(GetCurrentProcessId());
  CHECK(by_id.queried);
  CHECK(by_id.query_status >= 0);
  CHECK(current.level == by_id.level);
  CHECK(current.type == by_id.type);
  CHECK(current.audit == by_id.audit);
  CHECK(current.signer == by_id.signer);
}

TEST_CASE("QueryProcess of 0xFFFFFFFE equals the default ProtectionState") {
  const ProtectionState state = QueryProcess(0xFFFFFFFEul);
  const ProtectionState expected{};
  CHECK(state.level == expected.level);
  CHECK(state.type == expected.type);
  CHECK(state.audit == expected.audit);
  CHECK(state.signer == expected.signer);
  CHECK(state.Describe() == expected.Describe());
}

TEST_CASE("IsElevated matches TokenElevation on the current token") {
  HANDLE raw = nullptr;
  REQUIRE(OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw));
  TOKEN_ELEVATION elevation{};
  DWORD returned = 0;
  const BOOL ok = GetTokenInformation(raw, TokenElevation, &elevation,
                                      sizeof(elevation), &returned);
  CloseHandle(raw);
  const bool token_elevated = (ok != FALSE) && (elevation.TokenIsElevated != 0);
  CHECK(IsElevated() == token_elevated);
}

TEST_CASE("QuerySecureBootEnabled is queried xor a nonempty error") {
  const SecureBootState state = QuerySecureBootEnabled();
  if (state.queried) {
    CHECK(state.error.empty());
  } else if (state.error.find("Secure Boot key is absent") == 0) {
    CHECK(state.error.find("Secure Boot key is absent") == 0);
  } else {
    CHECK(state.error.find("UEFISecureBootEnabled is absent") == 0);
  }
}
