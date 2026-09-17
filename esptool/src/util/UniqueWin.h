#pragma once

#include <Windows.h>
#include <objbase.h>
#include <winsvc.h>

#include <string>

#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool {

inline void CloseScm(SC_HANDLE handle) noexcept { CloseServiceHandle(handle); }
inline void CloseReg(HKEY key) noexcept { RegCloseKey(key); }

using UniqueServiceHandle = UniqueCloser<SC_HANDLE, CloseScm>;
using UniqueRegKey = UniqueCloser<HKEY, CloseReg>;

inline void DeleteAttributeListOnly(
    LPPROC_THREAD_ATTRIBUTE_LIST list) noexcept {
  DeleteProcThreadAttributeList(list);
}

// Backing store must outlive this closer. Delete only — never HeapFree a
// vector<byte> list (the vector owns the bytes).
using UniqueLaunchAttributeList =
    UniqueCloser<LPPROC_THREAD_ATTRIBUTE_LIST, DeleteAttributeListOnly>;

struct ScmService {
  UniqueServiceHandle manager;
  UniqueServiceHandle service;
};

// OpenSCManager + OpenService only. CreateService stays at the call site.
[[nodiscard]] inline bool OpenScmService(const std::wstring& service_name,
                                         DWORD manager_access,
                                         DWORD service_access, ScmService& out,
                                         std::string& error) {
  out.manager.reset(OpenSCManagerW(nullptr, nullptr, manager_access));
  if (!out.manager) {
    error = text::Win32Message("OpenSCManager failed", GetLastError());
    return false;
  }
  out.service.reset(
      OpenServiceW(out.manager.get(), service_name.c_str(), service_access));
  if (!out.service) {
    error = text::Win32Message("OpenService failed", GetLastError());
    return false;
  }
  return true;
}

// CoUninitialize only after a successful CoInitializeEx. RPC_E_CHANGED_MODE
// means the thread already has a different apartment; COM is usable.
class UniqueComApartment {
 public:
  UniqueComApartment() noexcept
      : hr_(CoInitializeEx(nullptr, COINIT_MULTITHREADED)) {}

  ~UniqueComApartment() {
    if (SUCCEEDED(hr_)) {
      CoUninitialize();
    }
  }

  UniqueComApartment(const UniqueComApartment&) = delete;
  UniqueComApartment& operator=(const UniqueComApartment&) = delete;

  [[nodiscard]] bool usable() const noexcept {
    return SUCCEEDED(hr_) || hr_ == RPC_E_CHANGED_MODE;
  }

 private:
  HRESULT hr_{};
};

}  // namespace esptool
