#include <doctest.h>

#include <string_view>

#include "esp/EspCatalog.h"

TEST_CASE("kTypedFilterExports slot 0 is empty and slot 10 is process") {
  using esptool::esp::kTypedFilterExports;

  CHECK(kTypedFilterExports.size() == 17);
  CHECK(std::string_view{kTypedFilterExports[0]}.empty());
  CHECK(std::string_view{kTypedFilterExports[10]} == "EspCreateProcessFilter");
}
