#pragma once

#include <initializer_list>
#include <string>
#include <string_view>
#include <vector>

#ifndef ESPTOOL_RULES_DIR
#define ESPTOOL_RULES_DIR "."
#endif

namespace esptool::test {

// Keeps wide-string storage alive for ParseOptions.
class WideArgv {
 public:
  explicit WideArgv(std::initializer_list<std::wstring_view> args) {
    store_.emplace_back(L"esptool");
    for (const std::wstring_view arg : args) {
      store_.emplace_back(arg);
    }
    ptrs_.reserve(store_.size());
    for (std::wstring& token : store_) {
      ptrs_.push_back(token.data());
    }
  }

  [[nodiscard]] int argc() const noexcept {
    return static_cast<int>(ptrs_.size());
  }

  [[nodiscard]] wchar_t** argv() noexcept { return ptrs_.data(); }

 private:
  std::vector<std::wstring> store_;
  std::vector<wchar_t*> ptrs_;
};

[[nodiscard]] inline std::string RulesFile(std::string_view leaf) {
  std::string path(ESPTOOL_RULES_DIR);
  if (!path.empty() && path.back() != '\\' && path.back() != '/') {
    path.push_back('\\');
  }
  path.append(leaf);
  return path;
}

}  // namespace esptool::test
