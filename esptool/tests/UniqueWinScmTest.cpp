#include <doctest.h>

#include "util/UniqueWin.h"

#include <Windows.h>
#include <winsvc.h>

#include <cstddef>
#include <string>
#include <vector>

TEST_CASE("OpenScmService fails closed for a missing service") {
  esptool::ScmService scm;
  std::string error;
  const bool opened = esptool::OpenScmService(
      L"esptool-ut-no-such-service-9e2f4c18", SC_MANAGER_CONNECT,
      SERVICE_QUERY_CONFIG, scm, error);
  CHECK_FALSE(opened);
  CHECK_FALSE(scm.service);
  CHECK_FALSE(error.empty());
  if (scm.manager) {
    CHECK(error.find("OpenService failed") == 0);
  } else {
    CHECK(error.find("OpenSCManager failed") == 0);
  }
}

TEST_CASE("UniqueLaunchAttributeList wraps InitializeProcThreadAttributeList") {
  SIZE_T size = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &size);
  REQUIRE(size > 0);

  std::vector<std::byte> buf(size);
  auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buf.data());
  REQUIRE(InitializeProcThreadAttributeList(list, 1, 0, &size));

  esptool::UniqueLaunchAttributeList closer(list);
  CHECK(closer);
}

TEST_CASE("UniqueComApartment pins an apartment") {
  const esptool::UniqueComApartment apartment;
  CHECK(apartment.usable());

  const HRESULT second = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
  const bool already_initialized =
      second == S_FALSE || second == RPC_E_CHANGED_MODE;
  CHECK(already_initialized);
  if (SUCCEEDED(second)) {
    CoUninitialize();
  }
}
