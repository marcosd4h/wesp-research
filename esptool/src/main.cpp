// wmain parses options, sets the log, enters a COM apartment for XmlLite,
// then Dispatch. Worker hop and DLL load are not here. The service and
// isolated children re-enter wmain independently.

#include <Windows.h>

#include <algorithm>
#include <array>
#include <cstdio>
#include <ranges>
#include <string>
#include <string_view>
#include <utility>

#include "cli/Commands.h"
#include "cli/Options.h"
#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueWin.h"

namespace {

[[nodiscard]] esptool::LogLevel ParseLevel(std::string_view value) {
  constexpr std::array kLevels =
      std::to_array<std::pair<std::string_view, esptool::LogLevel>>({
          {"trace", esptool::LogLevel::Trace},
          {"debug", esptool::LogLevel::Debug},
          {"warn", esptool::LogLevel::Warn},
          {"error", esptool::LogLevel::Error},
      });
  const auto found = std::ranges::find_if(kLevels, [&](const auto& entry) {
    return esptool::text::EqualsIgnoreCase(value, entry.first);
  });
  if (found != kLevels.end()) {
    return found->second;
  }
  return esptool::LogLevel::Info;
}

}  // namespace

int wmain(int argc, wchar_t** argv) {
  esptool::cli::Options options;
  std::string error;
  if (!esptool::cli::ParseOptions(argc, argv, options, error)) {
    std::fprintf(stderr, "%s\n", error.c_str());
    return 2;
  }
  if (options.help || options.command.empty()) {
    std::printf("%s\n", esptool::cli::Usage().c_str());
    return options.help ? 0 : 2;
  }

  esptool::LogLevel level = esptool::LogLevel::Info;
  if (!options.level.empty()) {
    level = ParseLevel(options.level);
  } else if (options.verbose) {
    level = esptool::LogLevel::Debug;
  }
  esptool::Log::SetLevel(level);
  if (!options.log_path.empty()) {
    if (!esptool::Log::AttachFile(options.log_path)) {
      std::fprintf(stderr, "could not open the log file: %s\n",
                   options.log_path.c_str());
    }
  }

  // XmlLite in the rule parser needs a COM apartment; the service and the
  // isolated child processes reenter here independently.
  esptool::UniqueComApartment apartment;
  const int status = esptool::cli::Dispatch(options);
  esptool::Log::DetachFile();
  return status;
}
