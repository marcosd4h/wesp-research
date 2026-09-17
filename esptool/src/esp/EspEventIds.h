#pragma once

#include <array>
#include <cstdint>

namespace esptool::esp {

constexpr std::uint32_t kEventThreadCreate = 1;
constexpr std::uint32_t kEventThreadStart = 2;
constexpr std::uint32_t kEventThreadTerminate = 3;
constexpr std::uint32_t kEventProcessCreate = 1000;
constexpr std::uint32_t kEventProcessTerminate = 1001;
constexpr std::uint32_t kEventProcessLoadImage = 1002;
constexpr std::uint32_t kEventFoCreate = 2000;
constexpr std::uint32_t kEventFoOpen = 2001;
constexpr std::uint32_t kEventFoRead = 2002;
constexpr std::uint32_t kEventFoWrite = 2003;
constexpr std::uint32_t kEventFoCleanup = 2004;
constexpr std::uint32_t kEventFsMin = 3000;
constexpr std::uint32_t kEventFsQueryOpen = 3007;
// Upper bound of the filesystem subset whose capability record carries the
// driver enforce-capable bit 0x02. FileUnlock (3009) and the KTM commit and
// rollback types (3010, 3011) do not carry that bit.
constexpr std::uint32_t kEventFsLockFile = 3008;
constexpr std::uint32_t kEventFsMax = 3011;
constexpr std::uint32_t kEventVolumeMin = 4000;
constexpr std::uint32_t kEventVolumeMax = 4002;
// Named volume types. VolumeDismount (4001) is the only volume type whose
// capability record does not carry the driver enforce-capable bit 0x02.
constexpr std::uint32_t kEventVolumeMount = kEventVolumeMin;
constexpr std::uint32_t kEventVolumeDismount = 4001;
constexpr std::uint32_t kEventVolumeFsctl = kEventVolumeMax;
static_assert(kEventFsLockFile == 3008, "fs lock-file boundary");
static_assert(kEventVolumeMount == 4000, "volume mount");
static_assert(kEventVolumeDismount == 4001, "volume dismount");
static_assert(kEventVolumeFsctl == 4002, "volume fsctl");
constexpr std::uint32_t kEventPipeCreate = 5000;
constexpr std::uint32_t kEventMailslotCreate = 6000;
constexpr std::uint32_t kEventRegCreateKey = 7000;
constexpr std::uint32_t kEventRegMax = 7014;
constexpr std::uint32_t kEventObCreateHandle = 8000;
constexpr std::uint32_t kEventObDuplicateHandle = 8001;
constexpr std::uint32_t kEventBootLoadDriver = 9000;

struct EventTypeRange {
  std::uint32_t first;
  std::uint32_t last;
};

inline constexpr std::array kSparseEventRanges{
    EventTypeRange{kEventThreadCreate, kEventThreadTerminate},
    EventTypeRange{kEventProcessCreate, kEventProcessLoadImage},
    EventTypeRange{kEventFoCreate, kEventFoCleanup},
    EventTypeRange{kEventFsMin, kEventFsMax},
    EventTypeRange{kEventVolumeMin, kEventVolumeMax},
    EventTypeRange{kEventPipeCreate, kEventPipeCreate},
    EventTypeRange{kEventMailslotCreate, kEventMailslotCreate},
    EventTypeRange{kEventRegCreateKey, kEventRegMax},
    EventTypeRange{kEventObCreateHandle, kEventObDuplicateHandle},
    EventTypeRange{kEventBootLoadDriver, kEventBootLoadDriver},
};

[[nodiscard]] constexpr bool IsSparseEventType(
    std::uint32_t event_type) noexcept {
  for (const EventTypeRange& range : kSparseEventRanges) {
    if (event_type >= range.first && event_type <= range.last) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] constexpr bool IsRegistryEventType(
    std::uint32_t event_type) noexcept {
  return event_type >= kEventRegCreateKey && event_type <= kEventRegMax;
}

[[nodiscard]] constexpr bool IsFoIoEvent(std::uint32_t event_type) noexcept {
  return event_type >= kEventFoCreate && event_type <= kEventFoCleanup;
}

[[nodiscard]] constexpr bool IsPipeEventType(
    std::uint32_t event_type) noexcept {
  return event_type == kEventFoOpen || event_type == kEventPipeCreate;
}

[[nodiscard]] constexpr bool NeedsTypedIoConfig(
    std::uint32_t event_type) noexcept {
  return IsFoIoEvent(event_type) || event_type == kEventPipeCreate;
}

[[nodiscard]] constexpr bool IsThreadEventType(
    std::uint32_t event_type) noexcept {
  return event_type >= kEventThreadCreate &&
         event_type <= kEventThreadTerminate;
}

}  // namespace esptool::esp
