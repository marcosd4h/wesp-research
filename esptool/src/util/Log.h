#pragma once

#include <string>
#include <string_view>

namespace esptool {

enum class LogLevel : int {
  Trace = 0,
  Debug = 1,
  Info = 2,
  Warn = 3,
  Error = 4,
};

// Process-wide logger. Writes to stderr and, when attached, to a log file.
// Thread-safe: the service and the notification listener both log.
class Log {
 public:
  static void SetLevel(LogLevel level) noexcept;
  [[nodiscard]] static LogLevel Level() noexcept;
  [[nodiscard]] static bool WouldLog(LogLevel level) noexcept;

  // Attaches a UTF-8 log file. Returns false when the file cannot be opened.
  [[nodiscard]] static bool AttachFile(const std::string& utf8_path);
  static void DetachFile();

  static void Write(LogLevel level, std::string_view message);

  static void Trace(std::string_view message) {
    Write(LogLevel::Trace, message);
  }
  static void Debug(std::string_view message) {
    Write(LogLevel::Debug, message);
  }
  static void Info(std::string_view message) { Write(LogLevel::Info, message); }
  static void Warn(std::string_view message) { Write(LogLevel::Warn, message); }
  static void Error(std::string_view message) {
    Write(LogLevel::Error, message);
  }
};

}  // namespace esptool
