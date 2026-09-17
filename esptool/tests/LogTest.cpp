#include <doctest.h>

#include "util/Log.h"

#include <chrono>
#include <filesystem>
#include <fstream>
#include <iterator>
#include <string>

namespace {

struct LevelGuard {
  ~LevelGuard() {
    esptool::Log::SetLevel(esptool::LogLevel::Info);
    esptool::Log::DetachFile();
  }
};

void RestoreInfoLevel() { esptool::Log::SetLevel(esptool::LogLevel::Info); }

std::filesystem::path UniqueTempLogPath() {
  return std::filesystem::temp_directory_path() /
         ("esptool_logtest_" +
          std::to_string(std::chrono::high_resolution_clock::now()
                             .time_since_epoch()
                             .count()) +
          ".log");
}

}  // namespace

TEST_CASE("Log WouldLog follows SetLevel") {
  using esptool::Log;
  using esptool::LogLevel;

  LevelGuard guard;
  constexpr LogLevel kAll[] = {LogLevel::Trace, LogLevel::Debug, LogLevel::Info,
                               LogLevel::Warn, LogLevel::Error};
  for (LogLevel set : kAll) {
    Log::SetLevel(set);
    CHECK(Log::Level() == set);
    for (LogLevel query : kAll) {
      const bool expected =
          static_cast<int>(query) >= static_cast<int>(set);
      CHECK(Log::WouldLog(query) == expected);
    }
  }
}

TEST_CASE("Log AttachFile appends an INFO line then DetachFile") {
  using esptool::Log;
  using esptool::LogLevel;

  RestoreInfoLevel();
  Log::DetachFile();

  const auto path = UniqueTempLogPath();
  REQUIRE(Log::AttachFile(path.string()));
  Log::Write(LogLevel::Info, "esptool-log-file-smoke");
  Log::DetachFile();

  std::string contents;
  {
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in);
    contents.assign(std::istreambuf_iterator<char>(in),
                    std::istreambuf_iterator<char>());
  }
  CHECK(contents.find("[INFO ]") != std::string::npos);
  CHECK(contents.find("esptool-log-file-smoke") != std::string::npos);
  RestoreInfoLevel();
}

TEST_CASE("Log AttachFile rejects an illegal path") {
  using esptool::Log;
  using esptool::LogLevel;

  LevelGuard guard;
  RestoreInfoLevel();
  Log::DetachFile();

  CHECK_FALSE(Log::AttachFile({}));

  const auto path = UniqueTempLogPath();
  REQUIRE(Log::AttachFile(path.string()));
  CHECK_FALSE(Log::AttachFile("?:\\esptool_illegal_log_path\\x.log"));

  const std::string after_failed =
      "esptool-log-after-failed-attach-" +
      std::to_string(std::chrono::high_resolution_clock::now()
                         .time_since_epoch()
                         .count());
  Log::Write(LogLevel::Info, after_failed);
  Log::DetachFile();

  std::string contents;
  {
    std::ifstream in(path, std::ios::binary);
    REQUIRE(in);
    contents.assign(std::istreambuf_iterator<char>(in),
                    std::istreambuf_iterator<char>());
  }
  CHECK(contents.find(after_failed) == std::string::npos);
}
