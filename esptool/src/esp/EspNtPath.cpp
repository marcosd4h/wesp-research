#include "esp/EspNtPath.h"

#include <Windows.h>
#include <sddl.h>
#include <winternl.h>

#include <cstdint>
#include <format>
#include <vector>

#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool::esp {
namespace {

constexpr ULONG kFileNameInformationClass = 9;

struct FileNameInformationBuf {
  ULONG file_name_length = 0;
  wchar_t file_name[512] = {};
};

[[nodiscard]] std::wstring QueryOnDiskFileName(HANDLE file) {
  using NtQueryInformationFileFn =
      NTSTATUS(NTAPI*)(HANDLE, PIO_STATUS_BLOCK, PVOID, ULONG, ULONG);
  const HMODULE ntdll = GetModuleHandleW(L"ntdll.dll");
  if (ntdll == nullptr || file == INVALID_HANDLE_VALUE) {
    return {};
  }
  const auto query = reinterpret_cast<NtQueryInformationFileFn>(
      GetProcAddress(ntdll, "NtQueryInformationFile"));
  if (query == nullptr) {
    return {};
  }
  FileNameInformationBuf info{};
  IO_STATUS_BLOCK iosb{};
  const NTSTATUS status =
      query(file, &iosb, &info, sizeof(info), kFileNameInformationClass);
  if (status < 0 || info.file_name_length == 0 ||
      (info.file_name_length & 1u) != 0) {
    return {};
  }
  const std::size_t chars = info.file_name_length / sizeof(wchar_t);
  if (chars == 0 || chars >= std::size(info.file_name)) {
    return {};
  }
  return std::wstring(info.file_name, chars);
}

[[nodiscard]] std::wstring DevicePrefixForDrive(wchar_t drive) {
  const wchar_t letter[] = {drive, L':', L'\0'};
  wchar_t device[MAX_PATH] = {};
  const DWORD written =
      QueryDosDeviceW(letter, device, static_cast<DWORD>(std::size(device)));
  if (written == 0 || device[0] == L'\0') {
    return {};
  }
  return device;
}

[[nodiscard]] std::wstring DevicePrefixFromFinalPath(std::wstring_view nt) {
  // \Device\HarddiskVolumeN\... → \Device\HarddiskVolumeN
  if (nt.size() < 9 || nt[0] != L'\\') {
    return {};
  }
  const std::size_t second = nt.find(L'\\', 1);
  if (second == std::wstring_view::npos) {
    return {};
  }
  const std::size_t third = nt.find(L'\\', second + 1);
  if (third == std::wstring_view::npos) {
    return std::wstring(nt);
  }
  return std::wstring(nt.substr(0, third));
}

[[nodiscard]] std::wstring ExpandWithOnDiskCasing(std::wstring_view win32,
                                                  std::wstring device) {
  if (device.empty() || win32.size() < 3) {
    return {};
  }
  std::wstring current(1, win32[0]);
  current.append(L":\\");
  std::wstring result = std::move(device);
  std::size_t pos = 2;
  while (pos < win32.size() && win32[pos] == L'\\') {
    ++pos;
  }
  while (pos < win32.size()) {
    const std::size_t next = win32.find(L'\\', pos);
    const std::wstring component(win32.substr(
        pos, next == std::wstring_view::npos ? std::wstring_view::npos
                                             : next - pos));
    if (component.empty()) {
      break;
    }
    const std::wstring query = current + component;
    WIN32_FIND_DATAW found{};
    UniqueFind search(FindFirstFileW(query.c_str(), &found));
    result.push_back(L'\\');
    if (search) {
      result.append(found.cFileName);
      current.append(found.cFileName);
    } else {
      result.append(component);
      current.append(component);
    }
    current.push_back(L'\\');
    if (next == std::wstring_view::npos) {
      break;
    }
    pos = next + 1;
  }
  return result;
}

}  // namespace

bool LooksLikeNtPathPrefix(std::string_view value) noexcept {
  return value.size() > kNtPathPrefix.size() &&
         value.substr(0, kNtPathPrefix.size()) == kNtPathPrefix;
}

std::wstring ExpandWin32ToNtDevice(std::string_view win32) {
  const std::wstring wide = text::ToUtf16(win32);
  if (wide.size() < 2 || wide[1] != L':') {
    return wide;
  }
  UniqueHandle file(CreateFileW(
      wide.c_str(), 0, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
      nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr));
  std::wstring on_disk;
  std::wstring final_nt;
  if (file) {
    on_disk = QueryOnDiskFileName(file.get());
    wchar_t nt[MAX_PATH] = {};
    const DWORD written = GetFinalPathNameByHandleW(
        file.get(), nt, static_cast<DWORD>(std::size(nt)), VOLUME_NAME_NT);
    if (written > 0 && written < std::size(nt) && nt[0] == L'\\') {
      final_nt.assign(nt, written);
    }
  }
  std::wstring device = DevicePrefixForDrive(wide[0]);
  if (device.empty() && !final_nt.empty()) {
    device = DevicePrefixFromFinalPath(final_nt);
  }
  if (!device.empty()) {
    std::wstring walked = ExpandWithOnDiskCasing(wide, device);
    if (!walked.empty()) {
      return walked;
    }
  }
  if (!device.empty() && !on_disk.empty()) {
    if (on_disk[0] != L'\\') {
      device.push_back(L'\\');
    }
    device.append(on_disk);
    return device;
  }
  if (!final_nt.empty()) {
    return final_nt;
  }
  if (!device.empty() && wide.size() > 2) {
    device.append(wide.substr(2));
    return device;
  }
  return wide;
}

std::wstring ExpandRegistryPath(std::string_view value) {
  std::string_view body = value;
  if (LooksLikeNtPathPrefix(body)) {
    body = body.substr(kNtPathPrefix.size());
  }
  const std::wstring wide = text::ToUtf16(body);
  if (wide.size() >= 10 &&
      _wcsnicmp(wide.c_str(), L"\\Registry\\", 10) == 0) {
    return wide;
  }
  auto strip_prefix = [&](std::wstring_view prefix) -> std::wstring_view {
    if (wide.size() >= prefix.size() &&
        _wcsnicmp(wide.c_str(), prefix.data(), prefix.size()) == 0) {
      std::wstring_view rest = std::wstring_view(wide).substr(prefix.size());
      if (!rest.empty() && rest.front() == L'\\') {
        rest.remove_prefix(1);
      }
      return rest;
    }
    return {};
  };
  if (const std::wstring_view rest = strip_prefix(L"HKLM");
      rest.data() != nullptr || wide.size() >= 4) {
    if (_wcsnicmp(wide.c_str(), L"HKLM", 4) == 0) {
      std::wstring out = L"\\Registry\\Machine";
      const std::wstring_view tail = strip_prefix(L"HKLM");
      if (!tail.empty()) {
        out.push_back(L'\\');
        out.append(tail);
      }
      return out;
    }
  }
  if (wide.size() >= 18 &&
      _wcsnicmp(wide.c_str(), L"HKEY_LOCAL_MACHINE", 18) == 0) {
    std::wstring out = L"\\Registry\\Machine";
    std::wstring_view rest = std::wstring_view(wide).substr(18);
    if (!rest.empty() && rest.front() == L'\\') {
      rest.remove_prefix(1);
    }
    if (!rest.empty()) {
      out.push_back(L'\\');
      out.append(rest);
    }
    return out;
  }
  if (wide.size() >= 4 && _wcsnicmp(wide.c_str(), L"HKCR", 4) == 0) {
    std::wstring out = L"\\Registry\\Machine\\Software\\Classes";
    std::wstring_view rest = std::wstring_view(wide).substr(4);
    if (!rest.empty() && rest.front() == L'\\') {
      rest.remove_prefix(1);
    }
    if (!rest.empty()) {
      out.push_back(L'\\');
      out.append(rest);
    }
    return out;
  }
  if (wide.size() >= 3 && _wcsnicmp(wide.c_str(), L"HKU", 3) == 0) {
    std::wstring out = L"\\Registry\\User";
    std::wstring_view rest = std::wstring_view(wide).substr(3);
    if (!rest.empty() && rest.front() == L'\\') {
      rest.remove_prefix(1);
    }
    if (!rest.empty()) {
      out.push_back(L'\\');
      out.append(rest);
    }
    return out;
  }
  if ((wide.size() >= 4 && _wcsnicmp(wide.c_str(), L"HKCU", 4) == 0) ||
      (wide.size() >= 17 &&
       _wcsnicmp(wide.c_str(), L"HKEY_CURRENT_USER", 17) == 0)) {
    HANDLE raw = nullptr;
    UniqueHandle token;
    if (OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &raw)) {
      token = UniqueHandle(raw);
    }
    std::wstring sid = L".DEFAULT";
    if (token) {
      DWORD needed = 0;
      GetTokenInformation(token.get(), TokenUser, nullptr, 0, &needed);
      if (needed > 0) {
        std::vector<std::uint8_t> buffer(needed);
        if (GetTokenInformation(token.get(), TokenUser, buffer.data(), needed,
                                &needed)) {
          const auto* user = reinterpret_cast<TOKEN_USER*>(buffer.data());
          LPWSTR sid_text = nullptr;
          if (user != nullptr && user->User.Sid != nullptr &&
              ConvertSidToStringSidW(user->User.Sid, &sid_text)) {
            sid = sid_text;
            LocalFree(sid_text);
          }
        }
      }
    }
    std::wstring out = L"\\Registry\\User\\";
    out.append(sid);
    std::wstring_view rest = wide.size() >= 17 &&
                                     _wcsnicmp(wide.c_str(),
                                               L"HKEY_CURRENT_USER", 17) == 0
                                 ? std::wstring_view(wide).substr(17)
                                 : std::wstring_view(wide).substr(4);
    if (!rest.empty() && rest.front() == L'\\') {
      rest.remove_prefix(1);
    }
    if (!rest.empty()) {
      out.push_back(L'\\');
      out.append(rest);
    }
    return out;
  }
  return wide;
}

std::wstring ExpandFilterValue(std::string_view value) {
  if (LooksLikeNtPathPrefix(value)) {
    std::wstring expanded =
        ExpandWin32ToNtDevice(value.substr(kNtPathPrefix.size()));
    Log::Info(std::format("filter-ntpath {}", text::ToUtf8(expanded)));
    return expanded;
  }
  return text::ToUtf16(value);
}

}  // namespace esptool::esp
