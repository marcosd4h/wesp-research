#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

#include "esp/EspTypes.h"
#include "util/UniqueHandle.h"

namespace esptool::esp {

// One resolved (or unresolved) export of espclient.dll.
struct ExportDescriptor {
  std::string name;
  std::uint8_t arity = 0;
  std::string signature;
  FARPROC address = nullptr;
};

// Runtime linker for espclient.dll.
//
// The library is loaded with LoadLibraryExW and every export is resolved with
// GetProcAddress. No import library is used, so the tool runs against any
// compatible espclient.dll found at run time.
class EspApi {
 public:
  // Maximum recovered export arity. Four pointer-sized slots cover every case.
  static constexpr std::size_t kMaxArity = 4;

  EspApi() = default;
  ~EspApi();

  EspApi(const EspApi&) = delete;
  EspApi& operator=(const EspApi&) = delete;
  EspApi(EspApi&&) = delete;
  EspApi& operator=(EspApi&&) = delete;

  // Loads the library. When explicit_path is empty, the executable directory
  // and the default search order are tried. Returns false on failure; use
  // LastErrorMessage for the reason.
  [[nodiscard]] bool Load(const std::wstring& explicit_path = {});
  void Unload();

  [[nodiscard]] bool IsLoaded() const noexcept {
    return static_cast<bool>(module_);
  }
  [[nodiscard]] const std::wstring& LoadedPath() const noexcept {
    return loaded_path_;
  }
  [[nodiscard]] const std::string& LastErrorMessage() const noexcept {
    return last_error_;
  }

  [[nodiscard]] const std::vector<ExportDescriptor>& Exports() const noexcept {
    return exports_;
  }
  [[nodiscard]] std::size_t ExportCount() const noexcept {
    return exports_.size();
  }
  [[nodiscard]] std::size_t ResolvedCount() const noexcept;
  [[nodiscard]] std::vector<std::string> Missing() const;
  [[nodiscard]] const ExportDescriptor* Find(
      std::string_view name) const noexcept;

  [[nodiscard]] FARPROC Resolve(std::string_view name) const noexcept;

  // Resolves an export to a typed function pointer.
  template <typename Function>
  [[nodiscard]] Function Typed(std::string_view name) const noexcept {
    return reinterpret_cast<Function>(Resolve(name));
  }

  // Invokes a resolved export through the ABI-neutral raw signature.
  [[nodiscard]] std::int64_t Invoke(
      const ExportDescriptor& descriptor,
      const std::array<std::uintptr_t, kMaxArity>& arguments) const noexcept;

 private:
  esptool::UniqueModule module_;
  std::wstring loaded_path_;
  std::string last_error_;
  std::vector<ExportDescriptor> exports_ = BuildCatalog();

  static std::vector<ExportDescriptor> BuildCatalog();
};

}  // namespace esptool::esp
