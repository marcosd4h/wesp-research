#include <doctest.h>

#include "ppl/ProtectedService.h"

#include <Windows.h>

#include <string>

using esptool::ppl::RunForeground;
using esptool::ppl::RunService;
using esptool::ppl::Uninstall;

TEST_CASE("RunService empty name returns ERROR_INVALID_PARAMETER") {
  const int status = RunService(L"", false);
  CHECK(status == static_cast<int>(ERROR_INVALID_PARAMETER));
}

TEST_CASE("RunForeground empty name returns ERROR_INVALID_PARAMETER") {
  const int status = RunForeground(L"", false);
  CHECK(status == static_cast<int>(ERROR_INVALID_PARAMETER));
}

TEST_CASE("Uninstall missing service fail-closes with a nonempty error") {
  // Install is live-only (CreateService can succeed on an elevated box); host
  // tests never call it.
  std::string error;
  CHECK_FALSE(Uninstall(L"esptool-ut-no-such-service-9e2f4c18", error));
  if (error.find("OpenSCManager failed") == 0) {
    CHECK(error.find("OpenSCManager failed") == 0);
  } else {
    CHECK(error.find("OpenService failed") == 0);
  }
}
