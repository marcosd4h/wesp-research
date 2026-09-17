#pragma once

#include <cstddef>
#include <cstdint>

#include "esp/EspEventIds.h"

namespace esptool::esp {

constexpr std::size_t kRuleFoIoConfigPtrOffset = 96;
constexpr std::size_t kRuleEventConfigPtrOffset = kRuleFoIoConfigPtrOffset;
constexpr std::size_t kFoIoFileObjectFilterOffset = 936;
constexpr std::size_t kFoIoConfigSize = 2048;
static_assert(kFoIoConfigSize >= 1728,
              "covers pipe-create 1680 and fo-open 1728");

struct CfgQuerySlot {
  std::size_t include;
  [[nodiscard]] constexpr std::size_t count() const noexcept {
    return include + 16;
  }
  [[nodiscard]] constexpr std::size_t ptr() const noexcept {
    return include + 24;
  }
};

constexpr std::size_t kCfgThreadIncludeOffset = 48;
constexpr std::size_t kCfgProcessIncludeOffset = 568;
constexpr std::size_t kCfgFileObjectIncludeOffset = 960;
constexpr std::size_t kCfgPipeIncludeOffset = 1096;
constexpr std::size_t kCfgFoTargetOffset = 1056;
constexpr std::uint32_t kCfgIncludeEnabled = 1;
constexpr std::uint32_t kFoTargetPipe = 3;

inline constexpr CfgQuerySlot kCfgThreadSlot{kCfgThreadIncludeOffset};
inline constexpr CfgQuerySlot kCfgProcessSlot{kCfgProcessIncludeOffset};
inline constexpr CfgQuerySlot kCfgFileObjectSlot{kCfgFileObjectIncludeOffset};
inline constexpr CfgQuerySlot kCfgPipeSlot{kCfgPipeIncludeOffset};

constexpr std::size_t kCfgThreadQueryCountOffset = kCfgThreadSlot.count();
constexpr std::size_t kCfgThreadQueryPtrOffset = kCfgThreadSlot.ptr();
constexpr std::size_t kCfgProcessQueryCountOffset = kCfgProcessSlot.count();
constexpr std::size_t kCfgProcessQueryPtrOffset = kCfgProcessSlot.ptr();
constexpr std::size_t kCfgFileObjectQueryCountOffset =
    kCfgFileObjectSlot.count();
constexpr std::size_t kCfgFileObjectQueryPtrOffset = kCfgFileObjectSlot.ptr();
constexpr std::size_t kCfgPipeQueryCountOffset = kCfgPipeSlot.count();
constexpr std::size_t kCfgPipeQueryPtrOffset = kCfgPipeSlot.ptr();

constexpr std::size_t kCfgMailslotIncludeOffset = 1384;
inline constexpr CfgQuerySlot kCfgMailslotSlot{kCfgMailslotIncludeOffset};
constexpr std::size_t kCfgMailslotQueryCountOffset = kCfgMailslotSlot.count();
constexpr std::size_t kCfgMailslotQueryPtrOffset = kCfgMailslotSlot.ptr();

static_assert(kCfgThreadQueryCountOffset == 64);
static_assert(kCfgThreadQueryPtrOffset == 72);
static_assert(kCfgProcessQueryCountOffset == 584);
static_assert(kCfgProcessQueryPtrOffset == 592);
static_assert(kCfgFileObjectQueryCountOffset == 976);
static_assert(kCfgFileObjectQueryPtrOffset == 984);
static_assert(kCfgPipeQueryCountOffset == 1112);
static_assert(kCfgPipeQueryPtrOffset == 1120);
static_assert(kCfgMailslotQueryCountOffset == 1400);
static_assert(kCfgMailslotQueryPtrOffset == 1408);
// EspRsSendUpdateRules copies FoCreate RuleMessageParts+376 to kernel
// message +216 (EventModify kind). Kind 0 is empty; rewrite then
// returns E_INVALIDARG.
constexpr std::size_t kFoIoRuleMessageKindOffset = 376;
static_assert(kFoIoRuleMessageKindOffset == 376);

// property_bindings_from_ffi copies 16-byte records from +40 / count +36.
// process_argument_from_source uses source kind 3 index 0 for the child.
struct alignas(8) ProcessPropertyBindingRaw {
  std::uint64_t source_kind = 3;
  std::uint64_t field_index = 0;
};
static_assert(sizeof(ProcessPropertyBindingRaw) == 16,
              "property_bindings_from_ffi record is 16");
static_assert(alignof(ProcessPropertyBindingRaw) >= 8,
              "property binding pointer must be 8-aligned");

struct alignas(8) PropertyQueryStore {
  std::int32_t process_ids[4] = {6, 20, 1, 2};
  std::int32_t thread_ids[2] = {1, 2};
  std::int32_t pipe_ids[1] = {1};
  std::int32_t file_object_ids[3] = {1, 9, 28};
  std::int32_t registry_ids[2] = {1, 2};
  std::int32_t mailslot_ids[1] = {1};
  std::int32_t pad = 0;
  ProcessPropertyBindingRaw child_bind{};
};
static_assert(alignof(PropertyQueryStore) >= 8,
              "query arrays must be 8-aligned");

struct alignas(8) FoIoConfigBlob {
  std::uint8_t bytes[kFoIoConfigSize]{};
};
static_assert(alignof(FoIoConfigBlob) >= 8,
              "FO_CONFIG pointer must be 8-aligned");
static_assert(sizeof(FoIoConfigBlob) == kFoIoConfigSize, "FO_CONFIG blob size");
static_assert(kEventFoCleanup - kEventFoCreate == 4, "Fo* cases are 2000-2004");

}  // namespace esptool::esp
