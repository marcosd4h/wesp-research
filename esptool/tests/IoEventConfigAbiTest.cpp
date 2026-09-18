#include <doctest.h>

#include "esp/EspEventConfigAbi.h"
#include "esp/EspEventIds.h"
#include "esp/EspIoConfigAbi.h"
#include "esp/EspRuleAbi.h"

TEST_CASE("CfgQuerySlot count and ptr add 16 and 24 to include") {
  using esptool::esp::CfgQuerySlot;

  CHECK(CfgQuerySlot{0}.count() == 16);
  CHECK(CfgQuerySlot{0}.ptr() == 24);

  const CfgQuerySlot slot{48};
  CHECK(slot.include == 48);
  CHECK(slot.count() == 64);
  CHECK(slot.ptr() == 72);
}

TEST_CASE("Needs* config predicates match a numeric event matrix") {
  using esptool::esp::kEventBootLoadDriver;
  using esptool::esp::kEventFoCreate;
  using esptool::esp::kEventFsQueryOpen;
  using esptool::esp::kEventObCreateHandle;
  using esptool::esp::kEventPipeCreate;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventProcessLoadImage;
  using esptool::esp::kEventProcessTerminate;
  using esptool::esp::kEventThreadCreate;
  using esptool::esp::NeedsImageLoadConfig;
  using esptool::esp::NeedsProcessConfig;
  using esptool::esp::NeedsProcessCreateConfig;
  using esptool::esp::RestrictPipeTarget;

  CHECK(NeedsProcessCreateConfig(kEventProcessCreate));
  CHECK_FALSE(NeedsProcessCreateConfig(0));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventThreadCreate));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventProcessTerminate));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventProcessLoadImage));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventFoCreate));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventFsQueryOpen));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventPipeCreate));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventObCreateHandle));
  CHECK_FALSE(NeedsProcessCreateConfig(kEventBootLoadDriver));

  CHECK(NeedsProcessConfig(kEventProcessTerminate));
  CHECK_FALSE(NeedsProcessConfig(0));
  CHECK_FALSE(NeedsProcessConfig(kEventThreadCreate));
  CHECK_FALSE(NeedsProcessConfig(kEventProcessCreate));
  CHECK_FALSE(NeedsProcessConfig(kEventProcessLoadImage));
  CHECK_FALSE(NeedsProcessConfig(kEventFoCreate));
  CHECK_FALSE(NeedsProcessConfig(kEventFsQueryOpen));
  CHECK_FALSE(NeedsProcessConfig(kEventPipeCreate));
  CHECK_FALSE(NeedsProcessConfig(kEventObCreateHandle));
  CHECK_FALSE(NeedsProcessConfig(kEventBootLoadDriver));

  CHECK(NeedsImageLoadConfig(kEventProcessLoadImage));
  CHECK_FALSE(NeedsImageLoadConfig(0));
  CHECK_FALSE(NeedsImageLoadConfig(kEventThreadCreate));
  CHECK_FALSE(NeedsImageLoadConfig(kEventProcessCreate));
  CHECK_FALSE(NeedsImageLoadConfig(kEventProcessTerminate));
  CHECK_FALSE(NeedsImageLoadConfig(kEventFoCreate));
  CHECK_FALSE(NeedsImageLoadConfig(kEventFsQueryOpen));
  CHECK_FALSE(NeedsImageLoadConfig(kEventPipeCreate));
  CHECK_FALSE(NeedsImageLoadConfig(kEventObCreateHandle));
  CHECK_FALSE(NeedsImageLoadConfig(kEventBootLoadDriver));

  CHECK(RestrictPipeTarget(kEventPipeCreate));
  CHECK_FALSE(RestrictPipeTarget(0));
  CHECK_FALSE(RestrictPipeTarget(kEventThreadCreate));
  CHECK_FALSE(RestrictPipeTarget(kEventProcessCreate));
  CHECK_FALSE(RestrictPipeTarget(kEventProcessTerminate));
  CHECK_FALSE(RestrictPipeTarget(kEventProcessLoadImage));
  CHECK_FALSE(RestrictPipeTarget(kEventFoCreate));
  CHECK_FALSE(RestrictPipeTarget(kEventFsQueryOpen));
  CHECK_FALSE(RestrictPipeTarget(kEventObCreateHandle));
  CHECK_FALSE(RestrictPipeTarget(kEventBootLoadDriver));
}

TEST_CASE("EventModifyKindForEvent maps FO, OB, FS, and unknown events") {
  using esptool::esp::EventModifyKindForEvent;
  using esptool::esp::kEventFoCreate;
  using esptool::esp::kEventFsQueryOpen;
  using esptool::esp::kEventObCreateHandle;
  using esptool::esp::kEventObDuplicateHandle;
  using esptool::esp::kEventPipeCreate;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventThreadCreate;

  CHECK(EventModifyKindForEvent(kEventFoCreate) == 3);
  CHECK(EventModifyKindForEvent(kEventObCreateHandle) == 1);
  CHECK(EventModifyKindForEvent(kEventObDuplicateHandle) == 2);
  CHECK(EventModifyKindForEvent(kEventFsQueryOpen) == 4);
  CHECK(EventModifyKindForEvent(0) == 0);
  CHECK(EventModifyKindForEvent(kEventThreadCreate) == 0);
  CHECK(EventModifyKindForEvent(kEventProcessCreate) == 0);
  CHECK(EventModifyKindForEvent(kEventPipeCreate) == 0);
}

TEST_CASE("SupportsEnforcePayload covers FoCreate and the enforce-compat set") {
  using esptool::esp::kEventFoCreate;
  using esptool::esp::kEventFoOpen;
  using esptool::esp::kEventFsQueryOpen;
  using esptool::esp::kEventObCreateHandle;
  using esptool::esp::kEventObDuplicateHandle;
  using esptool::esp::kEventPipeCreate;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventRegCreateKey;
  using esptool::esp::SupportsEnforcePayload;
  // FoCreate is accepted by the unpatched client. EspEnforceCompat removes the
  // client gate in memory so the driver-ready types (1000, 2001-2003,
  // 3000-3006/3008, 4000/4002) also yield an enforcing descriptor.
  // ProcessCreate has a driver-side deny path that the compat patch makes
  // reachable through the client ABI.
  CHECK(SupportsEnforcePayload(kEventFoCreate));
  CHECK(SupportsEnforcePayload(kEventProcessCreate));
  CHECK(SupportsEnforcePayload(kEventFoOpen));
  // Registry is excluded: the class cannot block (no create/open disposition)
  // and 7003 cannot build an enforcing descriptor (E_INVALIDARG).
  CHECK_FALSE(SupportsEnforcePayload(kEventRegCreateKey));
  CHECK_FALSE(SupportsEnforcePayload(7003));
  // Driver-impossible: 3007/8000/8001 carry live record 0x19 (bit 0x02 clear)
  // and 3007's class has no filesystem disposition.
  CHECK_FALSE(SupportsEnforcePayload(kEventFsQueryOpen));
  CHECK_FALSE(SupportsEnforcePayload(kEventObCreateHandle));
  CHECK_FALSE(SupportsEnforcePayload(kEventObDuplicateHandle));
  // 5000/6000 have bit 0x02 set but the driver has no pre-operation DENY
  // callback; 9000 carries live mask 0x07 yet has no DENY callback either.
  CHECK_FALSE(SupportsEnforcePayload(kEventPipeCreate));
  CHECK_FALSE(SupportsEnforcePayload(6000));
  CHECK_FALSE(SupportsEnforcePayload(9000));
}
