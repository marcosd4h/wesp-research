#include <doctest.h>

#include <cstdint>

#include "esp/EspFilterAbi.h"

namespace {

struct CeilingRow {
  std::int32_t constructor;
  std::uint32_t ceiling;
};

struct PayloadRow {
  std::int32_t constructor;
  std::uint32_t property;
  esptool::esp::LeafPayloadKind kind;
};

constexpr CeilingRow kPropertyCeilings[] = {
    {esptool::esp::kFilterCtorClient, 1},
    {esptool::esp::kFilterCtorDesktop, 1},
    {esptool::esp::kFilterCtorRegistryKeyObject, 2},
    {esptool::esp::kFilterCtorPipe, 2},
    {esptool::esp::kFilterCtorMailslot, 2},
    {esptool::esp::kFilterCtorEvent, 3},
    {esptool::esp::kFilterCtorKtm, 3},
    {esptool::esp::kFilterCtorFileStream, 4},
    {esptool::esp::kFilterCtorRegistryKey, 4},
    {esptool::esp::kFilterCtorThread, 11},
    {esptool::esp::kFilterCtorToken, 12},
    {esptool::esp::kFilterCtorDisk, 13},
    {esptool::esp::kFilterCtorVolume, 16},
    {esptool::esp::kFilterCtorFile, 18},
    {esptool::esp::kFilterCtorProcess, 23},
    {esptool::esp::kFilterCtorFileObject, 28},
    {99, 0},
    {0, 0},
};

constexpr PayloadRow kLeafPayloads[] = {
    {esptool::esp::kFilterCtorClient, 1, esptool::esp::LeafPayloadKind::Bool},
    {esptool::esp::kFilterCtorEvent, 1, esptool::esp::LeafPayloadKind::Bool},
    {esptool::esp::kFilterCtorRegistryKeyObject, 1,
     esptool::esp::LeafPayloadKind::Bool},

    {esptool::esp::kFilterCtorEvent, 2, esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorFile, 2, esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorFileObject,
     esptool::esp::kFileObjectNumericProperty18,
     esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorFileObject,
     esptool::esp::kFileObjectNumericProperty28,
     esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorRegistryKeyObject, 2,
     esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorThread, 1, esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorToken, 3, esptool::esp::LeafPayloadKind::Numeric},
    {esptool::esp::kFilterCtorKtm, 2, esptool::esp::LeafPayloadKind::Numeric},

    {esptool::esp::kFilterCtorFile, 17, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorFileObject,
     esptool::esp::kFileObjectStringPropertyMin,
     esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorFileObject,
     esptool::esp::kFileObjectStringPropertyMax,
     esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorFileStream, 1,
     esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorRegistryKey, 1,
     esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorRegistryKey, 2,
     esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorProcess, 1, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorDesktop, 1, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorDisk, 1, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorVolume, 1, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorPipe, 1, esptool::esp::LeafPayloadKind::String},
    {esptool::esp::kFilterCtorMailslot, 1,
     esptool::esp::LeafPayloadKind::String},

    {esptool::esp::kFilterCtorProcess, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorToken, 1, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFile, 1, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorEvent, 3, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorKtm, 1, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorKtm, 3, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorThread, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorToken, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileStream, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileStream, 3, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileStream, 4, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorRegistryKey, 3,
     esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorRegistryKey, 4,
     esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorPipe, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorMailslot, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorDisk, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorVolume, 2, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorProcess, 23, esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileObject, 11,
     esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileObject, 17,
     esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileObject, 19,
     esptool::esp::LeafPayloadKind::None},
    {esptool::esp::kFilterCtorFileObject, 27,
     esptool::esp::LeafPayloadKind::None},
};

}  // namespace

TEST_CASE("PropertyCeiling maps every kFilterCtor and unknown constructors") {
  using esptool::esp::PropertyCeiling;

  for (const CeilingRow& row : kPropertyCeilings) {
    CHECK(PropertyCeiling(row.constructor) == row.ceiling);
  }
}

TEST_CASE("LeafPayload returns None for property 0 and ceiling plus one") {
  using esptool::esp::LeafPayload;
  using esptool::esp::LeafPayloadKind;
  using esptool::esp::PropertyCeiling;

  for (const CeilingRow& row : kPropertyCeilings) {
    CHECK(PropertyCeiling(row.constructor) == row.ceiling);
    CHECK(LeafPayload(row.constructor, 0) == LeafPayloadKind::None);
    CHECK(LeafPayload(row.constructor, row.ceiling + std::uint32_t{1}) ==
          LeafPayloadKind::None);
  }
}

TEST_CASE("LeafPayload maps Bool Numeric String and in-range None") {
  using esptool::esp::kFileObjectStringPropertyMax;
  using esptool::esp::kFileObjectStringPropertyMin;
  using esptool::esp::kFilterCtorFileObject;
  using esptool::esp::LeafPayload;
  using esptool::esp::LeafPayloadKind;

  for (const PayloadRow& row : kLeafPayloads) {
    CHECK(LeafPayload(row.constructor, row.property) == row.kind);
  }

  for (std::uint32_t property = kFileObjectStringPropertyMin;
       property <= kFileObjectStringPropertyMax; ++property) {
    CHECK(LeafPayload(kFilterCtorFileObject, property) ==
          LeafPayloadKind::String);
  }
}
