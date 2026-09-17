#pragma once

#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "esp/EspApi.h"
#include "esp/EspSession.h"

namespace esptool::esp {

// Outcome of exercising one export.
struct ExportOutcome {
  std::string name;
  std::uint8_t arity = 0;
  bool resolved = false;
  bool invoked = false;
  std::int64_t result = 0;
  std::string detail;
};

// Exercises every export of espclient.dll.
//
// The in-process sweep prepares a live client, queue, and notification, then
// invokes each resolved export with an argument vector classified from the
// export name. The isolated sweep spawns one child process per export so a call
// that faults cannot terminate the parent; the child returns the HRESULT as its
// exit code.
class EspExercise {
 public:
  EspExercise(const EspApi& api, EspSession& session)
      : api_(api), session_(session) {}

  [[nodiscard]] std::vector<ExportOutcome> RunInProcess();
  [[nodiscard]] std::vector<ExportOutcome> RunIsolated();

  // Calls one named export with a classified argument vector. Used by the
  // `call-one` command; returns the HRESULT.
  static std::int64_t CallOne(const EspApi& api, EspSession& session,
                              std::string_view name);

  // The CRT entry point is not a callable API.
  [[nodiscard]] static bool IsExcluded(std::string_view name);

 private:
  // Creates the queue and connects a no-op callback. Does not Arm.
  void PrepareSession();

  const EspApi& api_;
  EspSession& session_;
};

}  // namespace esptool::esp
