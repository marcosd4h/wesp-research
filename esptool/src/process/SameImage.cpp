// CreateProcessW of this image. LaunchWorker is the parent hop; Dispatch
// only decides whether to call it.

#include "process/SameImage.h"

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0A00
#endif
#include <Windows.h>
#include <processthreadsapi.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <format>
#include <string_view>
#include <vector>

#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"
#include "util/UniqueWin.h"

namespace esptool::process {
namespace {

constexpr wchar_t kWorkerFlag[] = L"--worker";
constexpr DWORD kTerminateDrainMs = 5000;

[[nodiscard]] bool IsExactWorkerFlag(std::wstring_view token) noexcept {
  return token == kWorkerFlag;
}

// Microsoft argv quoting: wrap when empty or when space/tab/newline/quote
// appears; double backslashes that precede a quote or the closing quote.
[[nodiscard]] std::wstring QuoteArgument(std::wstring_view argument) {
  const bool needs_quotes =
      argument.empty() ||
      argument.find_first_of(L" \t\n\v\"") != std::wstring_view::npos;
  if (!needs_quotes) {
    return std::wstring(argument);
  }

  std::wstring quoted;
  quoted.push_back(L'"');
  std::size_t backslashes = 0;
  for (const wchar_t ch : argument) {
    if (ch == L'\\') {
      ++backslashes;
      continue;
    }
    if (ch == L'"') {
      quoted.append(backslashes * 2 + 1, L'\\');
      quoted.push_back(L'"');
      backslashes = 0;
      continue;
    }
    quoted.append(backslashes, L'\\');
    quoted.push_back(ch);
    backslashes = 0;
  }
  quoted.append(backslashes * 2, L'\\');
  quoted.push_back(L'"');
  return quoted;
}

}  // namespace

std::wstring CurrentImagePath() {
  std::wstring buffer(MAX_PATH, L'\0');
  for (;;) {
    const DWORD length = GetModuleFileNameW(nullptr, buffer.data(),
                                            static_cast<DWORD>(buffer.size()));
    if (length == 0) {
      return {};
    }
    if (static_cast<std::size_t>(length) < buffer.size()) {
      buffer.resize(length);
      return buffer;
    }
    buffer.resize(buffer.size() * 2);
  }
}

namespace {

[[nodiscard]] std::wstring BuildCommandLine(
    const std::wstring& image, std::span<const std::wstring> arguments) {
  std::wstring command_line = QuoteArgument(image);
  for (const std::wstring& argument : arguments) {
    command_line.push_back(L' ');
    command_line.append(QuoteArgument(argument));
  }
  return command_line;
}

[[nodiscard]] std::vector<std::wstring> WorkerArguments(
    std::span<const std::wstring> tokens) {
  std::vector<std::wstring> arguments;
  arguments.reserve(tokens.size() + 1);
  arguments.emplace_back(kWorkerFlag);
  for (const std::wstring& token : tokens) {
    if (!IsExactWorkerFlag(token)) {
      arguments.push_back(token);
    }
  }
  return arguments;
}

[[nodiscard]] bool UsableStdHandle(HANDLE handle) noexcept {
  return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

[[nodiscard]] bool MarkInheritable(HANDLE handle, std::string& error) {
  DWORD flags = 0;
  if (!GetHandleInformation(handle, &flags)) {
    error = text::Win32Message("GetHandleInformation failed", GetLastError());
    return false;
  }
  if ((flags & HANDLE_FLAG_INHERIT) != 0) {
    return true;
  }
  if (!SetHandleInformation(handle, HANDLE_FLAG_INHERIT, HANDLE_FLAG_INHERIT)) {
    error = text::Win32Message(
        "SetHandleInformation(HANDLE_FLAG_INHERIT) failed", GetLastError());
    return false;
  }
  return true;
}

[[nodiscard]] UniqueLaunchAttributeList MakeHandleList(
    std::span<HANDLE> handles, std::vector<std::byte>& buffer,
    std::string& error) {
  SIZE_T bytes = 0;
  InitializeProcThreadAttributeList(nullptr, 1, 0, &bytes);
  if (bytes == 0) {
    error = text::Win32Message(
        "InitializeProcThreadAttributeList size probe failed", GetLastError());
    return {};
  }
  buffer.assign(bytes, std::byte{});
  auto* list = reinterpret_cast<LPPROC_THREAD_ATTRIBUTE_LIST>(buffer.data());
  if (!InitializeProcThreadAttributeList(list, 1, 0, &bytes)) {
    error = text::Win32Message("InitializeProcThreadAttributeList failed",
                               GetLastError());
    buffer.clear();
    return {};
  }
  UniqueLaunchAttributeList owned(list);
  if (!UpdateProcThreadAttribute(
          owned.get(), 0, PROC_THREAD_ATTRIBUTE_HANDLE_LIST, handles.data(),
          handles.size() * sizeof(HANDLE), nullptr, nullptr)) {
    error = text::Win32Message("UpdateProcThreadAttribute(HANDLE_LIST) failed",
                               GetLastError());
    return {};
  }
  return owned;
}

}  // namespace

LaunchOutcome RunSameImage(std::span<const std::wstring> arguments,
                           const LaunchOptions& options) {
  LaunchOutcome outcome;
  const std::wstring image = CurrentImagePath();
  if (image.empty()) {
    outcome.error = "could not resolve the current executable path";
    return outcome;
  }

  std::wstring command_line = BuildCommandLine(image, arguments);

  STARTUPINFOEXW startup_ex{};
  startup_ex.StartupInfo.cb = sizeof(startup_ex.StartupInfo);
  std::vector<std::byte> attribute_buffer;
  UniqueLaunchAttributeList attribute_list;
  DWORD creation_flags = options.hidden ? CREATE_NO_WINDOW : 0;
  BOOL inherit_handles = FALSE;

  const HANDLE std_input = GetStdHandle(STD_INPUT_HANDLE);
  const HANDLE std_output = GetStdHandle(STD_OUTPUT_HANDLE);
  const HANDLE std_error = GetStdHandle(STD_ERROR_HANDLE);

  if (options.inherit_stdio) {
    std::array<HANDLE, 3> inherit{};
    std::size_t count = 0;
    const std::array<HANDLE, 3> candidates{std_input, std_output, std_error};
    for (const HANDLE handle : candidates) {
      if (!UsableStdHandle(handle)) {
        continue;
      }
      if (!MarkInheritable(handle, outcome.error)) {
        return outcome;
      }
      inherit[count++] = handle;
    }
    if (count > 0) {
      attribute_list = MakeHandleList(std::span<HANDLE>(inherit.data(), count),
                                      attribute_buffer, outcome.error);
      if (!attribute_list) {
        return outcome;
      }
      startup_ex.StartupInfo.cb = sizeof(startup_ex);
      startup_ex.StartupInfo.dwFlags = STARTF_USESTDHANDLES;
      startup_ex.StartupInfo.hStdInput = std_input;
      startup_ex.StartupInfo.hStdOutput = std_output;
      startup_ex.StartupInfo.hStdError = std_error;
      startup_ex.lpAttributeList = attribute_list.get();
      creation_flags |= EXTENDED_STARTUPINFO_PRESENT;
      inherit_handles = TRUE;
    }
  }

  PROCESS_INFORMATION information{};
  const BOOL created = CreateProcessW(
      image.c_str(), command_line.data(), nullptr, nullptr, inherit_handles,
      creation_flags, nullptr, nullptr, &startup_ex.StartupInfo, &information);
  if (!created) {
    outcome.error = text::Win32Message("CreateProcessW failed", GetLastError());
    return outcome;
  }

  UniqueHandle process(information.hProcess);
  UniqueHandle thread(information.hThread);
  information.hProcess = nullptr;
  information.hThread = nullptr;

  const DWORD waited = WaitForSingleObject(process.get(), options.wait_ms);
  if (waited == WAIT_TIMEOUT) {
    outcome.timed_out = true;
    if (options.terminate_on_timeout) {
      TerminateProcess(process.get(), options.timeout_exit_code);
      WaitForSingleObject(process.get(), kTerminateDrainMs);
      outcome.exit_code = options.timeout_exit_code;
    } else {
      outcome.error = "the worker process did not finish in time";
      return outcome;
    }
  } else if (waited != WAIT_OBJECT_0) {
    outcome.error =
        text::Win32Message("WaitForSingleObject failed", GetLastError());
    return outcome;
  }

  if (!outcome.timed_out || !options.terminate_on_timeout) {
    DWORD exit_code = 0;
    if (!GetExitCodeProcess(process.get(), &exit_code)) {
      outcome.error =
          text::Win32Message("GetExitCodeProcess failed", GetLastError());
      return outcome;
    }
    outcome.exit_code = exit_code;
  }

  outcome.created = true;
  return outcome;
}

LaunchOutcome LaunchWorker(const cli::Options& options) {
  LaunchOutcome outcome;
  if (options.worker) {
    outcome.error = "internal error: worker process attempted a parent hop";
    return outcome;
  }
  std::vector<std::wstring> arguments = WorkerArguments(options.tokens);
  const auto has_arg = [&](std::wstring_view flag) {
    return std::ranges::any_of(
        arguments, [&](const std::wstring& arg) { return arg == flag; });
  };
  if (options.no_provision && !has_arg(L"--no-provision")) {
    arguments.emplace_back(L"--no-provision");
  }
  if (options.clear_attribute && !has_arg(L"--clear-attribute")) {
    arguments.emplace_back(L"--clear-attribute");
  }
  if (options.no_auto_provision && !has_arg(L"--no-auto-provision")) {
    arguments.emplace_back(L"--no-auto-provision");
  }
  if (options.force_provision && !has_arg(L"--force-provision")) {
    arguments.emplace_back(L"--force-provision");
  }
  LaunchOptions launch;
  launch.inherit_stdio = true;
  launch.wait_ms = INFINITE;
  outcome = RunSameImage(arguments, launch);
  if (!outcome.created) {
    // Session 0 SYSTEM parents often have std handles that cannot join a
    // HANDLE_LIST. Retry with inherit-none; that is not an inherit-all
    // fallback.
    launch.inherit_stdio = false;
    LaunchOutcome retry = RunSameImage(arguments, launch);
    if (retry.created) {
      retry.error.clear();
      return retry;
    }
    if (!outcome.error.empty() && !retry.error.empty()) {
      retry.error = std::format("{}; retry without stdio inherit: {}",
                                outcome.error, retry.error);
    }
    return retry;
  }
  return outcome;
}

}  // namespace esptool::process
