#include <doctest.h>
#include "cli/Options.h"
#include "process/SameImage.h"

#include <Windows.h>

#include <string>
#include <string_view>
#include <vector>

using esptool::cli::Options;
using esptool::process::CurrentImagePath;
using esptool::process::LaunchOutcome;
using esptool::process::LaunchWorker;

namespace {

constexpr std::string_view kWorkerHopError =
    "internal error: worker process attempted a parent hop";

}  // namespace

TEST_CASE("CurrentImagePath matches GetModuleFileNameW of this image") {
  std::vector<wchar_t> buffer(MAX_PATH);
  DWORD length = 0;
  for (;;) {
    length = GetModuleFileNameW(nullptr, buffer.data(),
                                static_cast<DWORD>(buffer.size()));
    REQUIRE(length != 0);
    if (static_cast<std::size_t>(length) < buffer.size()) {
      break;
    }
    buffer.resize(buffer.size() * 2);
  }
  const std::wstring expected(buffer.data(), length);
  CHECK(CurrentImagePath() == expected);
}

TEST_CASE("LaunchWorker fails closed when Options.worker is already set") {
  // RunSameImage is live-only (CreateProcessW of this image); host tests never
  // call it. Do not call LaunchWorker with worker=false either.
  Options options;
  options.worker = true;
  const LaunchOutcome outcome = LaunchWorker(options);
  CHECK_FALSE(outcome.created);
  CHECK(outcome.error == kWorkerHopError);
}
