#pragma once

#include <cstddef>
#include <cstdint>

#include "esp/EspEnforceCompat.h"
#include "esp/EspEventIds.h"
#include "esp/EspIoConfigAbi.h"
#include "esp/EspRuleAbi.h"

namespace esptool::esp {

constexpr std::size_t kProcessConfigFilterOffset = 8;
constexpr std::size_t kProcessConfigBindingCountOffset = 36;
constexpr std::size_t kProcessConfigBindingPtrOffset = 40;
constexpr std::size_t kProcessConfigQueryCountOffset = 48;
constexpr std::size_t kProcessConfigQueryPtrOffset = 56;
// ProcessConfig::new reads the nested ProcessConfig pointer at +384.
// try_as_ffi writes that same nested pointer at output +392.
constexpr std::size_t kProcessConfigNestedOffset = 384;
constexpr std::uint64_t kProcessFieldSourceEvent = 3;
constexpr std::uint64_t kProcessFieldIndexChild = 0;
constexpr std::size_t kImageLoadFileObjectOffset = 392;
constexpr std::size_t kImageLoadFileObjectFilterOffset =
    kImageLoadFileObjectOffset + kProcessConfigFilterOffset;
constexpr std::size_t kRegistryConfigFilterOffset = 8;
constexpr std::size_t kRegistryConfigQueryCountOffset = 48;
constexpr std::size_t kRegistryConfigQueryPtrOffset = 56;

static_assert(kProcessConfigBindingCountOffset == 36);
static_assert(kProcessConfigBindingPtrOffset == 40);
static_assert(kProcessConfigQueryCountOffset == 48);
static_assert(kProcessConfigQueryPtrOffset == 56);
static_assert(kProcessConfigNestedOffset == 384);
static_assert(kImageLoadFileObjectOffset == 392);
static_assert(kImageLoadFileObjectFilterOffset == 400);

[[nodiscard]] constexpr bool NeedsProcessCreateConfig(
    std::uint32_t event_type) noexcept {
  return event_type == kEventProcessCreate;
}

[[nodiscard]] constexpr bool NeedsProcessConfig(
    std::uint32_t event_type) noexcept {
  return event_type == kEventProcessTerminate;
}

[[nodiscard]] constexpr bool NeedsImageLoadConfig(
    std::uint32_t event_type) noexcept {
  return event_type == kEventProcessLoadImage;
}

[[nodiscard]] constexpr bool RestrictPipeTarget(
    std::uint32_t event_type) noexcept {
  return event_type == kEventPipeCreate;
}

[[nodiscard]] constexpr std::uint32_t EventModifyKindForEvent(
    std::uint32_t event_type) noexcept {
  if (event_type == kEventFoCreate) {
    return kEventModifyKindFoCreate;
  }
  if (event_type == kEventObCreateHandle) {
    return 1;
  }
  if (event_type == kEventObDuplicateHandle) {
    return 2;
  }
  if (event_type == kEventFsQueryOpen) {
    return 4;
  }
  return 0;
}

// esptool builds an FoCreate access-mask modify payload for the enforcing
// selector. The other event types that carry an event modify kind need their
// own payload structure, which is not implemented. Measured live on build
// 10.0.29641: an ObCreateHandle (8000) enforcing rule is accepted by
// EspCreateRule and then rejected by EspUpdateRules with E_INVALIDARG
// (0x80070057), and the target operation completes.
//
// ProcessCreate does not use the minifilter descriptor path at all. The driver
// has a working process deny path: its process-creation notify routine consumes
// the engine decision and writes PS_CREATE_NOTIFY_INFO.CreationStatus from the
// same five-entry status table. That path is not reachable through the client
// ABI, because EspCreateRule rejects the enforcing descriptor for event type
// 1000 with E_INVALIDARG even when a modify kind is forced, measured live on the
// same build. The client therefore refuses the enforcing action for every event
// type except FoCreate, which is the only combination with a constructible
// descriptor and a matching payload.
// The enforcing selector is accepted by the client for two event types only.
// Measured on build 10.0.29667 with the descriptor modify kind forced to 1 so
// the descriptor would reach the client validation (every filter built S_OK):
// `EspCreateRule` returns S_OK for event type 2000 (natural kind 3) and 8000
// (kind 1), and E_INVALIDARG for 1000, 2002, 2003, 2004, 3000, 3007, 3011,
// 4000, 4002, 5000, 6000, 7000, 8001, and 9000. Event type 8000 then fails at
// `EspUpdateRules` with E_INVALIDARG, so 2000 is the only event type that
// completes the install and enforces. A nonzero modify kind is necessary but
// not sufficient: 3007 carries kind 4 and is still rejected by the client.
// The enforcing selector is accepted by the client for three event types, and
// only one of them survives the driver batch validation. Measured on build
// 10.0.29667 by testing each event type with its natural modify kind and with
// kinds 1 through 4 forced (every filter built S_OK, so these are descriptor
// outcomes):
//
//   EspCreateRule S_OK + EspUpdateRules S_OK          -> 2000 (kind 3)
//   EspCreateRule S_OK + EspUpdateRules E_INVALIDARG  -> 8000 (kind 1),
//                                                        8001 (kind 2)
//   EspCreateRule E_INVALIDARG                        -> 1000, 2002, 2004, 3000,
//                                                        3007, 3011, 4000, 5000,
//                                                        6000, 7000, 9000
//
// The client validates the kind against the event type: for 8000 only kind 1 is
// accepted and for 8001 only kind 2. Event type 3007 is assigned kind 4 by
// EventModifyKindForEvent yet is rejected for every kind, so the kind mapping and
// the enforcing acceptance set are separate gates. Only 2000 completes the
// install, so the enforcing action is refused early for every other type instead
// of failing later with an opaque E_INVALIDARG.
//
// EspEnforceCompat::ApplyFromFfiCompatPatch removes that client-side gate in
// memory (see esp/EspEnforceCompat.h), so the enforcing descriptor becomes
// constructible for the driver-ready set. SupportsEnforcePayload accepts
// FoCreate and every enforce-compat event type. 8000 and 8001 stay false because
// their live-recorded capability record 0x19 has bit 0x02 clear; 3007 stays false
// because its class has no filesystem disposition; 5000 and 6000 stay false
// because their callbacks do not write a disposition; 9000 stays false because it
// has no capability record on this build and no disposition callback either; and
// 2004 stays false because its capability mask 0x09 has bit 0x02 clear.
[[nodiscard]] constexpr bool SupportsEnforcePayload(
    std::uint32_t event_type) noexcept {
  return event_type == kEventFoCreate || IsEnforceCompatEventType(event_type);
}

// Event-modify kind to write into the enforcing descriptor. FoCreate and every
// enforce-compat event type share the FoCreate kind-3 AccessMask path, because
// the patched client routes every type through EventModify::from_ffi's FoCreate
// arm. The historical 3007/8000/8001 mappings (4/1/2) stay reachable for their
// non-enforce monitor and notify uses.
[[nodiscard]] constexpr std::uint32_t EnforceModifyKindForEvent(
    std::uint32_t event_type) noexcept {
  if (SupportsEnforcePayload(event_type)) {
    return kEventModifyKindFoCreate;
  }
  return EventModifyKindForEvent(event_type);
}

}  // namespace esptool::esp
