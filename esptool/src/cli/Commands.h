#pragma once

#include "cli/Options.h"

namespace esptool::cli {

// Loads espclient.dll and runs the requested command. Returns the process exit
// code: 0 on success, 1 on a runtime failure, 2 on a usage or load error.
[[nodiscard]] int Dispatch(const Options& options);

}  // namespace esptool::cli
