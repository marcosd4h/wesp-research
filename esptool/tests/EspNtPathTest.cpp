#include <Windows.h>
#include <doctest.h>

#include "esp/EspNtPath.h"

static std::wstring QueryDosDeviceCPrefix() {
  wchar_t buf[512] = {};
  const DWORD n = QueryDosDeviceW(L"C:", buf, static_cast<DWORD>(std::size(buf)));
  REQUIRE(n != 0);
  const std::wstring device(buf);
  REQUIRE_FALSE(device.empty());
  return device;
}

TEST_CASE("LooksLikeNtPathPrefix requires more than the $nt: token") {
  using esptool::esp::LooksLikeNtPathPrefix;

  CHECK_FALSE(LooksLikeNtPathPrefix(""));
  CHECK_FALSE(LooksLikeNtPathPrefix("$nt:"));
  CHECK_FALSE(LooksLikeNtPathPrefix("foo"));
  CHECK(LooksLikeNtPathPrefix("$nt:C:\\Windows"));
}

TEST_CASE("LooksLikeNtDevicePath accepts Device, ??, and DosDevices prefixes") {
  using esptool::esp::LooksLikeNtDevicePath;

  CHECK(LooksLikeNtDevicePath("\\Device\\"));
  CHECK(LooksLikeNtDevicePath("\\Device\\HarddiskVolume1\\Windows"));
  CHECK(LooksLikeNtDevicePath("\\??\\C:\\Windows"));
  CHECK(LooksLikeNtDevicePath("\\DosDevices\\C:"));

  CHECK_FALSE(LooksLikeNtDevicePath(""));
  CHECK_FALSE(LooksLikeNtDevicePath("foo"));
  CHECK_FALSE(LooksLikeNtDevicePath("C:\\Windows"));
  CHECK_FALSE(LooksLikeNtDevicePath("\\Device"));
  CHECK_FALSE(LooksLikeNtDevicePath("\\??"));
  CHECK_FALSE(LooksLikeNtDevicePath("\\DosDevices"));
}

TEST_CASE("ExpandRegistryPath leaves already-NT paths unchanged") {
  using esptool::esp::ExpandRegistryPath;

  const std::wstring exact =
      ExpandRegistryPath("\\Registry\\Machine\\Software");
  CHECK(exact == L"\\Registry\\Machine\\Software");
  CHECK(exact.find(L"\\Registry\\") == 0);

  const std::wstring mixed =
      ExpandRegistryPath("\\registry\\MACHINE\\Software");
  CHECK(mixed == L"\\registry\\MACHINE\\Software");
  CHECK(mixed.find(L"\\registry\\") == 0);

  const std::wstring from_nt_prefix =
      ExpandRegistryPath("$nt:\\Registry\\Machine\\Software");
  CHECK(from_nt_prefix == L"\\Registry\\Machine\\Software");
  CHECK(from_nt_prefix.find(L"\\Registry\\") == 0);
}

TEST_CASE("ExpandRegistryPath maps well-known hive aliases") {
  using esptool::esp::ExpandRegistryPath;

  CHECK(ExpandRegistryPath("HKLM") == L"\\Registry\\Machine");
  CHECK(ExpandRegistryPath("HKLM\\Software") ==
        L"\\Registry\\Machine\\Software");
  CHECK(ExpandRegistryPath("HKEY_LOCAL_MACHINE\\Software") ==
        L"\\Registry\\Machine\\Software");
  CHECK(ExpandRegistryPath("HKCR\\CLSID") ==
        L"\\Registry\\Machine\\Software\\Classes\\CLSID");
  CHECK(ExpandRegistryPath("HKU\\S-1-5-18") == L"\\Registry\\User\\S-1-5-18");
}

TEST_CASE("ExpandRegistryPath maps HKCU to the current user SID") {
  using esptool::esp::ExpandRegistryPath;

  const std::wstring hkcu = ExpandRegistryPath("HKCU");
  CHECK_FALSE(hkcu.empty());
  CHECK(hkcu.find(L"\\Registry\\User\\") == 0);
  CHECK(hkcu.find(L"\\Registry\\User\\") != std::wstring::npos);

  const std::wstring full = ExpandRegistryPath("HKEY_CURRENT_USER");
  CHECK_FALSE(full.empty());
  CHECK(full.find(L"\\Registry\\User\\") == 0);
  CHECK(full.find(L"\\Registry\\User\\") != std::wstring::npos);
}

TEST_CASE("ExpandRegistryPath returns UTF-16 of an unknown string") {
  using esptool::esp::ExpandRegistryPath;

  CHECK(ExpandRegistryPath("not-a-hive") == L"not-a-hive");
  CHECK(ExpandRegistryPath("Software") == L"Software");
}

TEST_CASE("ExpandFilterValue expands only $nt: values") {
  using esptool::esp::ExpandFilterValue;

  CHECK(ExpandFilterValue("plain-filter") == L"plain-filter");
  CHECK(ExpandFilterValue("C:\\Windows") == L"C:\\Windows");

  const std::wstring c_device = QueryDosDeviceCPrefix();

  const std::wstring from_root = ExpandFilterValue("$nt:C:\\");
  CHECK(from_root.compare(0, c_device.size(), c_device) == 0);

  const std::wstring from_win = ExpandFilterValue("$nt:C:\\Windows");
  CHECK(from_win.compare(0, c_device.size(), c_device) == 0);
  CHECK(from_win.find(L"Windows") != std::wstring::npos);
}

TEST_CASE("ExpandWin32ToNtDevice maps drive paths and copies short strings") {
  using esptool::esp::ExpandWin32ToNtDevice;

  const std::wstring c_device = QueryDosDeviceCPrefix();
  const std::wstring windows = ExpandWin32ToNtDevice("C:\\Windows");
  CHECK(windows.compare(0, c_device.size(), c_device) == 0);

  CHECK(ExpandWin32ToNtDevice("foo") == L"foo");
  CHECK(ExpandWin32ToNtDevice("ab") == L"ab");
  CHECK(ExpandWin32ToNtDevice("X") == L"X");
}
