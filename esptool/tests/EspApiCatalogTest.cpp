#include <doctest.h>

#include <array>
#include <cstdint>
#include <set>
#include <string>
#include <string_view>

#include "esp/EspApi.h"

TEST_CASE("Default EspApi has 121 unresolved exports and is not loaded") {
  const esptool::esp::EspApi api;

  CHECK(api.ExportCount() == 121);
  CHECK(api.ResolvedCount() == 0);
  CHECK_FALSE(api.IsLoaded());
  CHECK(api.LoadedPath().empty());
}

TEST_CASE("Find returns unresolved EspCreateRule and rejects unknown names") {
  const esptool::esp::EspApi api;

  const esptool::esp::ExportDescriptor* rule = api.Find("EspCreateRule");
  REQUIRE(rule != nullptr);
  CHECK(rule->name == "EspCreateRule");
  CHECK(rule->arity == 2);
  CHECK_FALSE(rule->signature.empty());
  CHECK(rule->address == nullptr);

  const esptool::esp::ExportDescriptor* unknown = api.Find("no-such-export");
  CHECK(unknown == nullptr);
}

TEST_CASE("Resolve returns nullptr for catalog and unknown names") {
  const esptool::esp::EspApi api;

  CHECK(api.Resolve("EspCreateRule") == nullptr);
  CHECK(api.Resolve("no-such-export") == nullptr);
}

TEST_CASE("Invoke on an unresolved descriptor returns 0 and kMaxArity is 4") {
  using esptool::esp::EspApi;

  const EspApi api;
  const esptool::esp::ExportDescriptor* rule = api.Find("EspCreateRule");
  REQUIRE(rule != nullptr);
  CHECK(rule->address == nullptr);

  const std::array<std::uintptr_t, EspApi::kMaxArity> none{};
  CHECK(api.Invoke(*rule, none) == 0);
  CHECK(EspApi::kMaxArity == 4);
}

TEST_CASE("Export names are unique nonempty and arity is at most kMaxArity") {
  using esptool::esp::EspApi;

  const EspApi api;
  std::set<std::string_view> names;

  for (const esptool::esp::ExportDescriptor& descriptor : api.Exports()) {
    CHECK_FALSE(descriptor.name.empty());
    CHECK(descriptor.arity <= EspApi::kMaxArity);
    const bool unique = names.insert(descriptor.name).second;
    CHECK(unique);
  }

  CHECK(names.size() == api.ExportCount());
  CHECK(names.size() == 121);
}

TEST_CASE("Load of a nonexistent explicit path fails without loading") {
  esptool::esp::EspApi api;
  const bool loaded = api.Load(
      L"C:\\this\\path\\does\\not\\exist\\esptool-ut\\espclient.dll");
  CHECK_FALSE(loaded);

  const bool mentions_could_not_load =
      api.LastErrorMessage().find("could not load") != std::string::npos;
  CHECK(mentions_could_not_load);
  CHECK_FALSE(api.IsLoaded());
  CHECK(api.LoadedPath().empty());
  CHECK(api.ResolvedCount() == 0);
  CHECK(api.ExportCount() == 121);

  const std::string load_error = api.LastErrorMessage();
  api.Unload();
  CHECK(api.LastErrorMessage() == load_error);
  CHECK_FALSE(api.IsLoaded());
  CHECK(api.ResolvedCount() == 0);
}

TEST_CASE("Known export arities match EspExports.inc") {
  const esptool::esp::EspApi api;

  const esptool::esp::ExportDescriptor* allocate =
      api.Find("EspAllocateEventNotification");
  REQUIRE(allocate != nullptr);
  CHECK(allocate->arity == 0);

  const esptool::esp::ExportDescriptor* connect =
      api.Find("EspConnectEventQueueWithCallback");
  REQUIRE(connect != nullptr);
  CHECK(connect->arity == 4);

  const esptool::esp::ExportDescriptor* filter =
      api.Find("EspCreateClientFilter");
  REQUIRE(filter != nullptr);
  CHECK(filter->arity == 4);
}
