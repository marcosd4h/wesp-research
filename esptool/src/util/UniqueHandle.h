#pragma once

#include <Windows.h>

#include <utility>

namespace esptool {

template <typename Handle>
[[nodiscard]] constexpr bool UsableNonEmpty(Handle handle) noexcept {
  return handle != Handle{};
}

[[nodiscard]] inline bool UsableKernel(HANDLE handle) noexcept {
  return handle != nullptr && handle != INVALID_HANDLE_VALUE;
}

inline void CloseKernel(HANDLE handle) noexcept { CloseHandle(handle); }
inline void CloseLibrary(HMODULE module) noexcept { FreeLibrary(module); }
inline void CloseFind(HANDLE handle) noexcept { FindClose(handle); }

// Move-only owner with a typed closer and an emptiness predicate.
// Kernel HANDLEs treat both nullptr and INVALID_HANDLE_VALUE as empty.
template <typename Handle, auto Close, auto Usable = UsableNonEmpty<Handle>>
class UniqueCloser {
 public:
  UniqueCloser() noexcept = default;

  explicit UniqueCloser(Handle handle) noexcept : handle_(Normalize(handle)) {}

  ~UniqueCloser() { reset(); }

  UniqueCloser(const UniqueCloser&) = delete;
  UniqueCloser& operator=(const UniqueCloser&) = delete;

  UniqueCloser(UniqueCloser&& other) noexcept : handle_(other.release()) {}

  UniqueCloser& operator=(UniqueCloser&& other) noexcept {
    if (this != &other) {
      reset();
      handle_ = other.release();
    }
    return *this;
  }

  [[nodiscard]] Handle get() const noexcept { return handle_; }
  [[nodiscard]] explicit operator bool() const noexcept {
    return Usable(handle_);
  }
  [[nodiscard]] Handle release() noexcept {
    return std::exchange(handle_, Handle{});
  }

  void reset(Handle handle = {}) noexcept {
    const Handle next = Normalize(handle);
    if (handle_ == next) {
      return;
    }
    if (Usable(handle_)) {
      Close(handle_);
    }
    handle_ = next;
  }

 private:
  [[nodiscard]] static Handle Normalize(Handle handle) noexcept {
    return Usable(handle) ? handle : Handle{};
  }

  Handle handle_{};
};

using UniqueHandle = UniqueCloser<HANDLE, CloseKernel, UsableKernel>;
using UniqueModule = UniqueCloser<HMODULE, CloseLibrary>;
using UniqueFind = UniqueCloser<HANDLE, CloseFind, UsableKernel>;

// Dynamic ntdll lookup. Returns nullptr when the module or export is absent.
template <typename Fn>
[[nodiscard]] Fn NtdllProc(const char* name) noexcept {
  const HMODULE module = GetModuleHandleW(L"ntdll.dll");
  if (module == nullptr) {
    return nullptr;
  }
  return reinterpret_cast<Fn>(GetProcAddress(module, name));
}

}  // namespace esptool
