#include <doctest.h>

#include <string_view>

#include "esp/EspRefAbi.h"

TEST_CASE("CanonicalQueryKind maps documented aliases and unknown") {
  using esptool::esp::CanonicalQueryKind;

  CHECK(CanonicalQueryKind("process-token") == "token");
  CHECK(CanonicalQueryKind("thread-token") == "token");
  CHECK(CanonicalQueryKind("stream") == "filestream");
  CHECK(CanonicalQueryKind("unknown") == "unknown");
}

TEST_CASE("KindHasReferenceCreate rejects kinds without create") {
  using esptool::esp::KindHasReferenceCreate;

  CHECK_FALSE(KindHasReferenceCreate("client"));
  CHECK_FALSE(KindHasReferenceCreate("ktm"));
  CHECK_FALSE(KindHasReferenceCreate("registry-key-object"));
  CHECK_FALSE(KindHasReferenceCreate("unknown"));
  CHECK_FALSE(KindHasReferenceCreate(""));
}

TEST_CASE("QueryExportForKind maps aliases and null kinds") {
  using esptool::esp::QueryExportForKind;

  CHECK(std::string_view{QueryExportForKind("process-token")} ==
        "EspQueryTokenProperties");
  CHECK(std::string_view{QueryExportForKind("thread-token")} ==
        "EspQueryTokenProperties");
  CHECK(std::string_view{QueryExportForKind("stream")} ==
        "EspQueryFileStreamProperties");

  CHECK(QueryExportForKind("event") == nullptr);
  CHECK(QueryExportForKind("unknown") == nullptr);
  CHECK(QueryExportForKind("") == nullptr);
}

TEST_CASE("SupportExportForKind maps aliases and null kinds") {
  using esptool::esp::SupportExportForKind;

  CHECK(std::string_view{SupportExportForKind("process-token")} ==
        "EspIsTokenPropertySupported");
  CHECK(std::string_view{SupportExportForKind("thread-token")} ==
        "EspIsTokenPropertySupported");
  CHECK(std::string_view{SupportExportForKind("stream")} ==
        "EspIsFileStreamPropertySupported");

  CHECK(SupportExportForKind("unknown") == nullptr);
  CHECK(SupportExportForKind("") == nullptr);
}
