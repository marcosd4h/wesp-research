#pragma once

#include <cstddef>
#include <cstdint>
#include <optional>
#include <string_view>

#include "esp/EspCore.h"

namespace esptool::esp {

constexpr std::uint32_t kActionQueueBacked = 1;

// Selector 4 stores the rule in the notify form with a zero event modify count.
// Measured on build 10.0.29641: the matching operation completes and only the
// queued notification is suppressed. It never blocks. Kept for telemetry
// suppression, not for enforcement.
constexpr std::uint32_t kActionNotifySuppress = 4;
constexpr std::uint32_t kActionRewrite = 5;
// The deny action is the enforcing selector. Selector 4 is the notify form and
// never blocks, so a deny constant must not alias it.
constexpr std::uint32_t kActionDeny = kActionRewrite;

// Named action tokens. "deny" resolves to the enforcing selector and denies the
// operation. "suppress" resolves to the notify form and does not block.
[[nodiscard]] constexpr std::uint32_t ActionSelectorForName(
    std::string_view action_name, std::uint32_t fallback) noexcept {
  if (action_name == "deny") {
    return kActionDeny;
  }
  if (action_name == "suppress") {
    return kActionNotifySuppress;
  }
  return fallback;
}

[[nodiscard]] constexpr bool ActionNeedsQueue(std::uint64_t action) noexcept {
  return (action != 0 ? static_cast<std::uint32_t>(action)
                      : kActionQueueBacked) == kActionQueueBacked;
}

// The queue requirement must be derived from the resolved selector. A named
// deny or suppress is a non-queue action even though its numeric action field is
// zero, which the raw-action predicate classifies as queue-backed.
[[nodiscard]] constexpr bool ActionNeedsQueueFor(
    std::uint64_t action, std::string_view action_name) noexcept {
  const std::uint32_t raw =
      action != 0 ? static_cast<std::uint32_t>(action) : kActionQueueBacked;
  return ActionSelectorForName(action_name, raw) == kActionQueueBacked;
}

static_assert(kActionDeny == kActionRewrite,
              "the deny action must be the enforcing selector, not selector 4");
static_assert(!ActionNeedsQueueFor(0, "deny"), "a named deny must not need a queue");
static_assert(!ActionNeedsQueueFor(0, "suppress"),
              "a named suppress must not need a queue");

// The queue requirement must be derived from the selector that is actually
// installed, which is the selector override when present. A document that sets
// only selector="5" or selector="6" is a non-queue action and must not create a
// user-mode session queue, because the persist store rejects a live queue
// pointer with E_INVALIDARG.
[[nodiscard]] constexpr bool ResolvedActionNeedsQueue(
    std::uint64_t action, std::string_view action_name,
    std::optional<std::uint32_t> selector_override) noexcept {
  const std::uint32_t raw =
      action != 0 ? static_cast<std::uint32_t>(action) : kActionQueueBacked;
  return selector_override.value_or(ActionSelectorForName(action_name, raw)) ==
         kActionQueueBacked;
}
constexpr std::uint32_t kActionCancel = 6;
constexpr std::uint32_t kActionMatchSubrules = 7;
constexpr std::uint32_t kLifetimeTransientFfi = 1;
constexpr std::uint32_t kLifetimePersistFfi = 3;
constexpr std::uint32_t kEventModifyBlobSize = 16;
// EspRsCreateRule copies +1088/+1092/+1096 into EventModify::from_ffi.
// *a3 is the inner kind (3 for FoCreate 2000), not the AccessMask count.
// a3[1] must be exactly 16. The pointer at +8 is the 16-byte list header.
constexpr std::uint32_t kEventModifyKindFoCreate = 3;
constexpr std::uint32_t kEventModifyAccessMaskBytes = 16;
constexpr std::uint32_t kRewriteAccessMask = 0x120089;
// EspRsCreateRule packs +1112..+1127 into v88. Selector 7 calls
// RuleActionMatchSubrules::new(count=low32(+1112), array=qword(+1120)).
constexpr std::size_t kRuleSubruleCountOffset = 1112;
constexpr std::size_t kRuleSubruleArrayOffset = 1120;
static_assert(kLifetimeTransientFfi == 1, "selector 1 + lifetime 0 is tag 92");
constexpr std::uint32_t kSubSelectorWritten = 1;
constexpr std::uint32_t kRuleUpdateOperationAdd = 1;

constexpr std::uint32_t kQueueDescriptorField16Accepted = 1;
constexpr std::uint32_t kQueueDescriptorField20Min = 1;
constexpr std::uint32_t kQueueDescriptorField20Max = 3;
constexpr std::uint32_t kQueueDescriptorField28Accepted = 1;

struct EventQueueDescriptor {
  Guid id{};
  std::uint32_t field16 = kQueueDescriptorField16Accepted;
  std::uint32_t field20 = kQueueDescriptorField20Min;
  std::uint32_t field24 = 0;
  std::uint32_t field28 = kQueueDescriptorField28Accepted;
};

static_assert(sizeof(EventQueueDescriptor) == 32,
              "EventQueueDescriptor must be 32 bytes");
static_assert(offsetof(EventQueueDescriptor, field16) == 16,
              "queue descriptor +16");

constexpr std::size_t kRuleConfigSize = 0x41C;
constexpr std::uint64_t kRuleOrderKey = 100;

struct RuleDescriptor {
  Guid id{};
  std::uint64_t opaque16 = kRuleOrderKey;
  std::uint32_t lifetime = 0;
  std::uint32_t flags = 0;
  std::uint32_t event_type = 0;
  std::uint8_t config[kRuleConfigSize]{};
  std::uint32_t event_modify_count = 0;
  std::uint32_t event_modify_size = 0;
  void* event_modify_ptr = nullptr;
  std::uint32_t action_selector = 0;
  std::uint32_t pad1108 = 0;
  void* event_queue = nullptr;
  std::uint8_t tail[32]{};
};

static_assert(offsetof(RuleDescriptor, lifetime) == 24,
              "rule +24 lifetime FFI");
static_assert(offsetof(RuleDescriptor, flags) == 28, "rule +28 flags");
static_assert(offsetof(RuleDescriptor, event_type) == 32, "rule +32");
static_assert(offsetof(RuleDescriptor, config) == 36, "rule +36");
static_assert(offsetof(RuleDescriptor, event_modify_count) == 1088,
              "rule +1088 EventModify kind when nonempty");
static_assert(kEventModifyKindFoCreate == 3, "FoCreate from_ffi kind is 3");
static_assert(kEventModifyAccessMaskBytes == 16,
              "from_ffi size for AccessMask is 16");
static_assert(offsetof(RuleDescriptor, event_modify_size) == 1092,
              "rule +1092 EventModify size");
static_assert(offsetof(RuleDescriptor, event_modify_ptr) == 1096,
              "rule +1096 EventModify ptr");
static_assert(offsetof(RuleDescriptor, action_selector) == 1104, "rule +1104");
static_assert(offsetof(RuleDescriptor, event_queue) == 1112, "rule +1112");
static_assert(sizeof(RuleDescriptor) >= 1128, "rule descriptor minimum");
static_assert(sizeof(RuleDescriptor) == 1152, "rule descriptor padded size");
static_assert(offsetof(RuleDescriptor, event_queue) == kRuleSubruleCountOffset,
              "selector 7 count is the low dword at +1112");
static_assert(offsetof(RuleDescriptor, tail) == kRuleSubruleArrayOffset,
              "selector 7 handle array pointer lives at +1120");

constexpr std::uint32_t kRewriteAccessMaskFlags = 1;

struct alignas(8) AccessMaskModification {
  std::uint32_t mask = kRewriteAccessMask;
  std::uint32_t flags = kRewriteAccessMaskFlags;
};
static_assert(sizeof(AccessMaskModification) == 8, "AccessMask entry is 8");
static_assert(alignof(AccessMaskModification) >= 4, "list entries 4-aligned");

struct alignas(8) EventModifyBlob {
  std::uint32_t count = 1;
  std::uint32_t pad = 0;
  void* entries = nullptr;
};
static_assert(sizeof(EventModifyBlob) == kEventModifyBlobSize,
              "EventModify list header is 16");
static_assert(offsetof(EventModifyBlob, entries) == 8, "entries ptr at +8");
static_assert(alignof(EventModifyBlob) >= 8, "EventModify ptr 8-aligned");

struct RuleUpdateEntry {
  std::uint32_t operation = kRuleUpdateOperationAdd;
  std::uint32_t pad = 0;
  void* rule = nullptr;
  std::uint64_t extra = 0;
};

static_assert(sizeof(RuleUpdateEntry) == 24,
              "RuleUpdateEntry must be 24 bytes");

struct ClientRegisterDescriptor {
  Guid id{};
  const wchar_t* name = nullptr;
  const wchar_t* altitude = nullptr;
};

static_assert(offsetof(ClientRegisterDescriptor, name) == 16, "register +16");
static_assert(offsetof(ClientRegisterDescriptor, altitude) == 24,
              "register +24");
static_assert(sizeof(ClientRegisterDescriptor) == 32,
              "register descriptor size");

}  // namespace esptool::esp
