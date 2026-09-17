#pragma once

#include <cstdint>
#include <span>
#include <string>
#include <vector>

#include "cli/Options.h"
#include "esp/EspTypes.h"

namespace esptool::process {

// How a same-image child is created and waited on.
struct LaunchOptions {
  bool inherit_stdio = false;
  bool hidden = false;
  std::uint32_t wait_ms = 0xFFFFFFFFu;
  bool terminate_on_timeout = false;
  std::uint32_t timeout_exit_code =
      static_cast<std::uint32_t>(esp::kStatusCancelled);
};

// Result of CreateProcessW on this image.
struct LaunchOutcome {
  bool created = false;
  bool timed_out = false;
  std::uint32_t exit_code = 1;
  std::string error;
};

// Absolute path of this image via GetModuleFileNameW. Empty on failure.
[[nodiscard]] std::wstring CurrentImagePath();

// Hardened CreateProcess of this module. Does not interpret --worker or role.
// lpApplicationName is GetModuleFileNameW (absolute, no PATH search).
[[nodiscard]] LaunchOutcome RunSameImage(
    std::span<const std::wstring> arguments, const LaunchOptions& options = {});

// Parent hop. Takes Options so a tokens-only call does not compile.
// Fails closed if options.worker is already set. Strips every exact --worker
// from tokens and prepends one --worker at the front, then waits infinitely.
[[nodiscard]] LaunchOutcome LaunchWorker(const cli::Options& options);

}  // namespace esptool::process
