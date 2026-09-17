#include <doctest.h>

#include <string>
#include <vector>

#include "esp/EspApi.h"
#include "esp/EspCore.h"
#include "esp/EspExercise.h"
#include "esp/EspSession.h"

// RunIsolated is live-only: it CreateProcessW-s this test image. Do not call it
// from host tests, and do not Load() a real espclient.dll here.

TEST_CASE("CallOne on excluded names returns kInvalidArg") {
  using esptool::esp::EspApi;
  using esptool::esp::EspExercise;
  using esptool::esp::EspSession;
  using esptool::esp::kInvalidArg;

  const EspApi api;
  EspSession session(api);
  CHECK_FALSE(api.IsLoaded());

  CHECK(EspExercise::CallOne(api, session, "_DllMainCRTStartup") ==
        kInvalidArg);
  CHECK(EspExercise::CallOne(api, session,
                             "EspCreateFileStreamReferenceById") ==
        kInvalidArg);
}

TEST_CASE("CallOne on unknown or unresolved catalog names returns kModNotFound") {
  using esptool::esp::EspApi;
  using esptool::esp::EspExercise;
  using esptool::esp::EspSession;
  using esptool::esp::kModNotFound;

  const EspApi api;
  EspSession session(api);
  CHECK_FALSE(api.IsLoaded());

  CHECK(EspExercise::CallOne(api, session, "no-such-export") == kModNotFound);
  CHECK(EspExercise::CallOne(api, session, "EspCreateRule") == kModNotFound);
}

TEST_CASE("RunInProcess on an unloaded EspApi seeds 121 uninvoked outcomes") {
  using esptool::esp::EspApi;
  using esptool::esp::EspExercise;
  using esptool::esp::EspSession;
  using esptool::esp::ExportOutcome;

  const EspApi api;
  EspSession session(api);
  CHECK_FALSE(api.IsLoaded());
  CHECK(api.ExportCount() == 121);
  CHECK(api.ResolvedCount() == 0);

  EspExercise exercise(api, session);
  const std::vector<ExportOutcome> outcomes = exercise.RunInProcess();
  CHECK(outcomes.size() == 121);

  std::size_t excluded_count = 0;
  for (const ExportOutcome& outcome : outcomes) {
    CHECK_FALSE(outcome.invoked);

    if (EspExercise::IsExcluded(outcome.name)) {
      ++excluded_count;
      const bool mentions_excluded =
          outcome.detail.find("excluded") != std::string::npos;
      CHECK(mentions_excluded);
    } else {
      const bool mentions_not_exported =
          outcome.detail.find("not exported") != std::string::npos;
      CHECK(mentions_not_exported);
    }
  }
  CHECK(excluded_count == 2);
}
