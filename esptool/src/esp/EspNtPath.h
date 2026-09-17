#pragma once

#include <string>
#include <string_view>

namespace esptool::esp {

inline constexpr std::string_view kNtPathPrefix = "$nt:";

[[nodiscard]] bool LooksLikeNtPathPrefix(std::string_view value) noexcept;

[[nodiscard]] inline bool LooksLikeNtDevicePath(std::string_view value) noexcept {
  return value.starts_with("\\Device\\") || value.starts_with("\\??\\") ||
         value.starts_with("\\DosDevices\\");
}

// QueryDosDevice of the drive letter, then the remainder of the Win32 path.
// Volume N is discovered at run time.
[[nodiscard]] std::wstring ExpandWin32ToNtDevice(std::string_view win32);

[[nodiscard]] std::wstring ExpandFilterValue(std::string_view value);

// HKLM\Software -> \Registry\Machine\Software. Already-NT paths are unchanged.
[[nodiscard]] std::wstring ExpandRegistryPath(std::string_view value);

}  // namespace esptool::esp
