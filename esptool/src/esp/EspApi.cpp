#include "esp/EspApi.h"

#include <Windows.h>

#include <algorithm>
#include <format>
#include <iterator>
#include <ranges>

#include "process/SameImage.h"
#include "util/StrHelpers.h"

namespace esptool::esp {
namespace {

std::wstring ExecutableDirectory() {
  const std::wstring path = process::CurrentImagePath();
  const std::size_t separator = path.find_last_of(L"\\/");
  if (separator == std::wstring::npos) {
    return {};
  }
  return path.substr(0, separator + 1);
}

}  // namespace

std::vector<ExportDescriptor> EspApi::BuildCatalog() {
  std::vector<ExportDescriptor> catalog;
  catalog.reserve(128);
#define ESP_EXPORT(name, arity, signature)                                    \
  catalog.push_back(ExportDescriptor{#name, static_cast<std::uint8_t>(arity), \
                                     signature, nullptr});
#include "esp/EspExports.inc"
#undef ESP_EXPORT
  return catalog;
}

EspApi::~EspApi() { Unload(); }

bool EspApi::Load(const std::wstring& explicit_path) {
  Unload();
  last_error_.clear();

  std::vector<std::wstring> candidates;
  if (!explicit_path.empty()) {
    // An explicit path is authoritative: a failure is reported rather than
    // silently satisfied by a different library.
    candidates.push_back(explicit_path);
  } else {
    const std::wstring directory = ExecutableDirectory();
    if (!directory.empty()) {
      candidates.push_back(directory + kEspClientDll);
    }
    candidates.push_back(kEspClientDll);
  }

  DWORD load_error = ERROR_MOD_NOT_FOUND;
  for (const std::wstring& candidate : candidates) {
    const bool has_directory =
        candidate.find_first_of(L"\\/") != std::wstring::npos;
    const DWORD flags = has_directory ? LOAD_WITH_ALTERED_SEARCH_PATH : 0;
    HMODULE module = LoadLibraryExW(candidate.c_str(), nullptr, flags);
    if (module == nullptr) {
      module = LoadLibraryW(candidate.c_str());
    }
    if (module != nullptr) {
      module_.reset(module);
      loaded_path_ = candidate;
      break;
    }
    load_error = GetLastError();
  }

  if (!module_) {
    const std::wstring attempted =
        explicit_path.empty() ? kEspClientDll : explicit_path;
    last_error_ = std::format("could not load {} (error {})",
                              text::ToUtf8(attempted), load_error);
    return false;
  }

  std::size_t resolved = 0;
  for (ExportDescriptor& descriptor : exports_) {
    const FARPROC address =
        GetProcAddress(module_.get(), descriptor.name.c_str());
    descriptor.address = address;
    if (address != nullptr) {
      ++resolved;
    }
  }

  if (resolved == 0) {
    last_error_ = "the loaded library exports none of the expected symbols";
    Unload();
    return false;
  }
  return true;
}

void EspApi::Unload() {
  module_.reset();
  loaded_path_.clear();
  for (ExportDescriptor& descriptor : exports_) {
    descriptor.address = nullptr;
  }
}

std::size_t EspApi::ResolvedCount() const noexcept {
  return static_cast<std::size_t>(
      std::ranges::count_if(exports_, [](const ExportDescriptor& descriptor) {
        return descriptor.address != nullptr;
      }));
}

std::vector<std::string> EspApi::Missing() const {
  std::vector<std::string> missing;
  std::ranges::copy(
      exports_ | std::views::filter([](const ExportDescriptor& descriptor) {
        return descriptor.address == nullptr;
      }) | std::views::transform([](const ExportDescriptor& descriptor) {
        return descriptor.name;
      }),
      std::back_inserter(missing));
  return missing;
}

const ExportDescriptor* EspApi::Find(std::string_view name) const noexcept {
  const auto found =
      std::ranges::find_if(exports_, [&](const ExportDescriptor& descriptor) {
        return descriptor.name == name;
      });
  return found == exports_.end() ? nullptr : &*found;
}

FARPROC EspApi::Resolve(std::string_view name) const noexcept {
  const ExportDescriptor* descriptor = Find(name);
  return descriptor != nullptr ? descriptor->address : nullptr;
}

std::int64_t EspApi::Invoke(
    const ExportDescriptor& descriptor,
    const std::array<std::uintptr_t, kMaxArity>& arguments) const noexcept {
  // Null address returns 0, which CallRaw/Record treat as S_OK if reached.
  // RunInProcess skips unresolved; CallOne returns kModNotFound first.
  if (descriptor.address == nullptr) {
    return 0;
  }
  const auto function = reinterpret_cast<RawExportFn>(descriptor.address);
  return function(arguments[0], arguments[1], arguments[2], arguments[3]);
}

}  // namespace esptool::esp
