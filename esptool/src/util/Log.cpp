#include "util/Log.h"

#include <share.h>

#include <atomic>
#include <cstdio>
#include <memory>
#include <mutex>
#include <string_view>

namespace esptool {
namespace {

std::mutex g_mutex;
std::atomic<LogLevel> g_level{LogLevel::Info};
std::unique_ptr<std::FILE, int (*)(std::FILE*)> g_file{nullptr, &std::fclose};

[[nodiscard]] const char* LevelTag(LogLevel level) noexcept {
  switch (level) {
    case LogLevel::Trace:
      return "TRACE";
    case LogLevel::Debug:
      return "DEBUG";
    case LogLevel::Info:
      return "INFO ";
    case LogLevel::Warn:
      return "WARN ";
    case LogLevel::Error:
      return "ERROR";
  }
  return "?????";
}

void WritePieces(std::FILE* file, LogLevel level,
                 std::string_view message) noexcept {
  std::fputc('[', file);
  std::fputs(LevelTag(level), file);
  std::fputs("] ", file);
  std::fwrite(message.data(), 1, message.size(), file);
  std::fputc('\n', file);
  std::fflush(file);
}

}  // namespace

void Log::SetLevel(LogLevel level) noexcept {
  g_level.store(level, std::memory_order_relaxed);
}

LogLevel Log::Level() noexcept {
  return g_level.load(std::memory_order_relaxed);
}

bool Log::WouldLog(LogLevel level) noexcept {
  return static_cast<int>(level) >=
         static_cast<int>(g_level.load(std::memory_order_relaxed));
}

bool Log::AttachFile(const std::string& utf8_path) {
  std::lock_guard<std::mutex> guard(g_mutex);
  g_file.reset();
  std::FILE* file = _fsopen(utf8_path.c_str(), "ab", _SH_DENYNO);
  if (file == nullptr) {
    return false;
  }
  g_file.reset(file);
  return true;
}

void Log::DetachFile() {
  std::lock_guard<std::mutex> guard(g_mutex);
  g_file.reset();
}

void Log::Write(LogLevel level, std::string_view message) {
  if (!WouldLog(level)) {
    return;
  }
  std::lock_guard<std::mutex> guard(g_mutex);
  WritePieces(stderr, level, message);
  if (g_file) {
    WritePieces(g_file.get(), level, message);
  }
}

}  // namespace esptool
