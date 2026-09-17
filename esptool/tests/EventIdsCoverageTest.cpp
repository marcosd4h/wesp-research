#include <doctest.h>

#include "esp/EspEventIds.h"

TEST_CASE("IsSparseEventType covers documented range literals") {
  using esptool::esp::IsSparseEventType;

  CHECK(IsSparseEventType(1));
  CHECK(IsSparseEventType(3));
  CHECK(IsSparseEventType(1000));
  CHECK(IsSparseEventType(1002));
  CHECK(IsSparseEventType(2000));
  CHECK(IsSparseEventType(3000));
  CHECK(IsSparseEventType(3011));
  CHECK(IsSparseEventType(4000));
  CHECK(IsSparseEventType(4002));
  CHECK(IsSparseEventType(5000));
  CHECK(IsSparseEventType(6000));
  CHECK(IsSparseEventType(7000));
  CHECK(IsSparseEventType(7014));
  CHECK(IsSparseEventType(8000));
  CHECK(IsSparseEventType(8001));
  CHECK(IsSparseEventType(9000));
}

TEST_CASE("IsSparseEventType rejects gaps and out-of-range identifiers") {
  using esptool::esp::IsSparseEventType;

  CHECK_FALSE(IsSparseEventType(0));
  CHECK_FALSE(IsSparseEventType(4));
  CHECK_FALSE(IsSparseEventType(12));
  CHECK_FALSE(IsSparseEventType(30));
  CHECK_FALSE(IsSparseEventType(999));
  CHECK_FALSE(IsSparseEventType(1003));
  CHECK_FALSE(IsSparseEventType(2005));
  CHECK_FALSE(IsSparseEventType(3012));
  CHECK_FALSE(IsSparseEventType(4003));
  CHECK_FALSE(IsSparseEventType(5001));
  CHECK_FALSE(IsSparseEventType(6001));
  CHECK_FALSE(IsSparseEventType(7015));
  CHECK_FALSE(IsSparseEventType(8002));
  CHECK_FALSE(IsSparseEventType(8999));
  CHECK_FALSE(IsSparseEventType(9001));
}

TEST_CASE("IsRegistryEventType is true only for 7000 through 7014") {
  using esptool::esp::IsRegistryEventType;

  CHECK_FALSE(IsRegistryEventType(6999));
  CHECK(IsRegistryEventType(7000));
  CHECK(IsRegistryEventType(7007));
  CHECK(IsRegistryEventType(7014));
  CHECK_FALSE(IsRegistryEventType(7015));
}

TEST_CASE("IsFoIoEvent is true only for 2000 through 2004") {
  using esptool::esp::IsFoIoEvent;

  CHECK_FALSE(IsFoIoEvent(1999));
  CHECK(IsFoIoEvent(2000));
  CHECK(IsFoIoEvent(2001));
  CHECK(IsFoIoEvent(2002));
  CHECK(IsFoIoEvent(2003));
  CHECK(IsFoIoEvent(2004));
  CHECK_FALSE(IsFoIoEvent(2005));
}

TEST_CASE("IsPipeEventType is true only for 2001 and 5000") {
  using esptool::esp::IsPipeEventType;

  CHECK_FALSE(IsPipeEventType(2000));
  CHECK(IsPipeEventType(2001));
  CHECK_FALSE(IsPipeEventType(2002));
  CHECK(IsPipeEventType(5000));
  CHECK_FALSE(IsPipeEventType(5001));
}

TEST_CASE("NeedsTypedIoConfig is true for FO family and 5000") {
  using esptool::esp::NeedsTypedIoConfig;

  CHECK(NeedsTypedIoConfig(2000));
  CHECK(NeedsTypedIoConfig(2001));
  CHECK(NeedsTypedIoConfig(2002));
  CHECK(NeedsTypedIoConfig(2003));
  CHECK(NeedsTypedIoConfig(2004));
  CHECK(NeedsTypedIoConfig(5000));
  CHECK_FALSE(NeedsTypedIoConfig(1000));
  CHECK_FALSE(NeedsTypedIoConfig(1999));
  CHECK_FALSE(NeedsTypedIoConfig(2005));
  CHECK_FALSE(NeedsTypedIoConfig(4999));
  CHECK_FALSE(NeedsTypedIoConfig(5001));
  CHECK_FALSE(NeedsTypedIoConfig(7000));
}
