#include <doctest.h>

#include "util/UniqueHandle.h"

#include <utility>

TEST_CASE("UniqueHandle default and INVALID_HANDLE_VALUE are empty") {
  const esptool::UniqueHandle empty;
  CHECK_FALSE(empty);
  CHECK(empty.get() == nullptr);

  const esptool::UniqueHandle invalid{INVALID_HANDLE_VALUE};
  CHECK_FALSE(invalid);
  CHECK(invalid.get() == nullptr);
}

TEST_CASE("UniqueHandle move constructor and assignment transfer ownership") {
  HANDLE first = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  REQUIRE(esptool::UsableKernel(first));
  HANDLE second = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  REQUIRE(esptool::UsableKernel(second));

  esptool::UniqueHandle owner(first);
  CHECK(owner);
  esptool::UniqueHandle moved(std::move(owner));
  CHECK(moved);
  CHECK_FALSE(owner);
  CHECK(moved.get() == first);

  esptool::UniqueHandle assigned(second);
  assigned = std::move(moved);
  CHECK(assigned);
  CHECK_FALSE(moved);
  CHECK(assigned.get() == first);
}

TEST_CASE("UniqueHandle release leaves the handle open") {
  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  REQUIRE(esptool::UsableKernel(event));
  {
    esptool::UniqueHandle owner(event);
    CHECK(owner.release() == event);
    CHECK_FALSE(owner);
  }
  CHECK(WaitForSingleObject(event, 0) == WAIT_TIMEOUT);
  CHECK(CloseHandle(event));
}

TEST_CASE("UsableKernel and UsableNonEmpty distinguish empty sentinels") {
  CHECK_FALSE(esptool::UsableKernel(nullptr));
  CHECK_FALSE(esptool::UsableKernel(INVALID_HANDLE_VALUE));
  CHECK_FALSE(esptool::UsableNonEmpty(HANDLE{}));
  CHECK(esptool::UsableNonEmpty(INVALID_HANDLE_VALUE));

  HANDLE event = CreateEventW(nullptr, TRUE, FALSE, nullptr);
  REQUIRE(event != nullptr);
  CHECK(esptool::UsableKernel(event));
  CHECK(esptool::UsableNonEmpty(event));
  CHECK(CloseHandle(event));
}

TEST_CASE("NtdllProc resolves NtClose and rejects an unknown name") {
  CHECK(esptool::NtdllProc<void*>("NtClose") != nullptr);
  CHECK(esptool::NtdllProc<void*>("NoSuchEsptoolExport") == nullptr);
}
