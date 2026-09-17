#pragma once

#include "esp/EspEventIds.h"
#include "esp/EspMemoryView.h"
#include "esp/EspNotifyAbi.h"

namespace esptool::esp {

[[nodiscard]] inline bool TryUnboxU32(const std::byte* boxed,
                                      std::uint32_t expect_type,
                                      std::uint32_t* out,
                                      NotifyReadableFn readable) noexcept {
  if (boxed == nullptr || out == nullptr) {
    return false;
  }
  std::uint32_t boxed_type = 0;
  if (!NotifyReadU32(boxed, kBoxedTypeOffset, &boxed_type, readable) ||
      boxed_type != expect_type) {
    return false;
  }
  return NotifyReadU32(boxed, kBoxedPayloadOffset, out, readable);
}

[[nodiscard]] inline bool TryUnboxPid(const std::byte* boxed,
                                      std::uint32_t* out,
                                      NotifyReadableFn readable) noexcept {
  if (TryUnboxU32(boxed, kBoxedTypeU32, out, readable) ||
      TryUnboxU32(boxed, kBoxedTypeInt32, out, readable)) {
    return true;
  }
  std::uint8_t tag = 0;
  if (ReadPod(boxed, kPropertyValueTagOffset, &tag, readable) &&
      tag == kPropertyValueTagU32) {
    return NotifyReadU32(boxed, kPropertyValueU32Offset, out, readable);
  }
  return false;
}

[[nodiscard]] inline bool IsNameBoxedType(std::uint32_t boxed_type) noexcept {
  return boxed_type == kBoxedTypePathString ||
         boxed_type == kBoxedTypeUnicodeString;
}

[[nodiscard]] inline bool TryReadQueryBagU32(
    const std::byte* params, std::size_t bag_offset, std::uint32_t min_count,
    std::uint32_t* out, NotifyReadableFn readable) noexcept {
  const std::byte* bag = nullptr;
  std::uint32_t count = 0;
  const std::byte* boxed = nullptr;
  if (!NotifyReadPtr(params, bag_offset, &bag, readable) ||
      !NotifyReadU32(bag, kObjectQueryCountOffset, &count, readable) ||
      count < min_count ||
      !NotifyReadPtr(bag, kObjectQueryPtrOffset, &boxed, readable)) {
    return false;
  }
  return TryUnboxPid(boxed, out, readable);
}

template <typename Predicate>
[[nodiscard]] inline bool FindQuerySlot(const std::byte* notification,
                                        const std::byte** slot,
                                        NotifyReadableFn readable,
                                        Predicate matches) noexcept {
  if (notification == nullptr || slot == nullptr || readable == nullptr) {
    return false;
  }
  std::uint32_t count = 0;
  const std::byte* array = nullptr;
  if (!NotifyReadU32(notification, kNotificationQueryCountOffset, &count,
                     readable) ||
      count == 0 || count > kNotificationQueryCountMax ||
      !NotifyReadPtr(notification, kNotificationQueryPtrOffset, &array,
                     readable)) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    const auto* cursor = QuerySlotAt(array, index, kQuerySlotStride);
    if (!matches(cursor, readable)) {
      continue;
    }
    *slot = cursor;
    return true;
  }
  return false;
}

[[nodiscard]] inline bool TryReadNotificationQuerySlot(
    const std::byte* notification, std::uint32_t property,
    const std::byte** slot, NotifyReadableFn readable) noexcept {
  return FindQuerySlot(
      notification, slot, readable,
      [property](const std::byte* cursor, NotifyReadableFn can_read) noexcept {
        std::uint32_t found = 0;
        return NotifyReadU32(cursor, kQuerySlotPropertyOffset, &found,
                             can_read) &&
               found == property;
      });
}

[[nodiscard]] inline bool TryReadNotificationQueryPid(
    const std::byte* notification, std::uint32_t* pid,
    NotifyReadableFn readable) noexcept {
  const std::byte* slot = nullptr;
  return TryReadNotificationQuerySlot(notification, kProcessQueryPropertyPid,
                                      &slot, readable) &&
         TryUnboxPid(slot, pid, readable);
}

[[nodiscard]] inline bool TryReadNotificationQueryNameSlot(
    const std::byte* notification, const std::byte** slot,
    NotifyReadableFn readable) noexcept {
  return FindQuerySlot(
      notification, slot, readable,
      [](const std::byte* cursor, NotifyReadableFn can_read) noexcept {
        std::uint32_t boxed_type = 0;
        return NotifyReadU32(cursor, kQuerySlotTypeOffset, &boxed_type,
                             can_read) &&
               IsNameBoxedType(boxed_type);
      });
}

[[nodiscard]] inline bool TryReadPidTidFromParams(
    const std::byte* params, std::uint32_t* pid, std::uint32_t* tid,
    NotifyReadableFn readable) noexcept {
  if (params == nullptr || pid == nullptr || tid == nullptr ||
      readable == nullptr) {
    return false;
  }
  bool any = false;
  for (std::size_t bag_offset : kProcessPidBagCandidates) {
    if (TryReadQueryBagU32(params, bag_offset, 1, pid, readable)) {
      any = true;
      break;
    }
  }
  if (TryReadQueryBagU32(params, kParamsTidBagOffset, 1, tid, readable)) {
    any = true;
  }
  return any;
}

[[nodiscard]] inline bool ScanSparseEventType(
    const std::byte* data, std::uint32_t* event_type, std::size_t* type_offset,
    NotifyReadableFn readable) noexcept {
  if (data == nullptr || event_type == nullptr || type_offset == nullptr ||
      readable == nullptr) {
    return false;
  }
  for (std::size_t offset = 0;
       offset + sizeof(std::uint32_t) <= kEventDataScanLimit;
       offset += sizeof(std::uint32_t)) {
    std::uint32_t value = 0;
    if (!NotifyReadU32(data, offset, &value, readable) ||
        !IsSparseEventType(value)) {
      continue;
    }
    if (!IsPipeEventType(value) && value < kEventProcessCreate) {
      continue;
    }
    *event_type = value;
    *type_offset = offset;
    return true;
  }
  return false;
}

[[nodiscard]] inline bool TryBindLayout(
    const std::byte* data, std::size_t type_off, std::size_t params_off,
    std::uint32_t* event_type, const std::byte** params, bool* uses_primary,
    bool primary, std::size_t* type_offset_out,
    NotifyReadableFn readable) noexcept {
  std::uint32_t type = 0;
  if (!NotifyReadU32(data, type_off, &type, readable) ||
      !IsSparseEventType(type)) {
    return false;
  }
  *event_type = type;
  *params = nullptr;
  *uses_primary = primary;
  *type_offset_out = type_off;
  const std::byte* bound = nullptr;
  if (NotifyReadPtr(data, params_off, &bound, readable)) {
    *params = bound;
  }
  return true;
}

enum class FoNameLayout { None, UnicodeString, InlineUtf16 };

[[nodiscard]] inline FoNameLayout ClassifyFoNotificationName(
    std::uint32_t event_type, const std::byte* notification,
    const std::byte** source, NotifyReadableFn readable) noexcept {
  if (notification == nullptr || source == nullptr || readable == nullptr) {
    return FoNameLayout::None;
  }
  *source = nullptr;
  const auto try_us = [&]() -> bool {
    std::uint16_t length = 0;
    const std::byte* buffer = nullptr;
    std::uint16_t first = 0;
    if (!NotifyReadU16(notification, kFoNotificationNameUsOffset, &length,
                       readable) ||
        length == 0 || (length & 1u) != 0 ||
        !NotifyReadPtr(notification, kFoNotificationNameUsOffset + 8, &buffer,
                       readable) ||
        buffer == nullptr || !NotifyReadU16(buffer, 0, &first, readable) ||
        first != kNtPathFirstWchar) {
      return false;
    }
    *source = notification + kFoNotificationNameUsOffset;
    return true;
  };
  const auto try_inline = [&]() -> bool {
    std::uint16_t first = 0;
    if (NotifyReadU16(notification, kFoNotificationInlineNameOffset, &first,
                      readable) &&
        first == kNtPathFirstWchar) {
      *source = notification + kFoNotificationInlineNameOffset;
      return true;
    }
    const std::byte* pointed = nullptr;
    if (NotifyReadPtr(notification, kFoNotificationNamePtrOffset, &pointed,
                      readable) &&
        pointed != nullptr && NotifyReadU16(pointed, 0, &first, readable) &&
        first == kNtPathFirstWchar) {
      *source = pointed;
      return true;
    }
    return false;
  };
  if (event_type == kEventFoCreate) {
    return try_us() ? FoNameLayout::UnicodeString : FoNameLayout::None;
  }
  if (event_type == kEventFoOpen) {
    return try_inline() ? FoNameLayout::InlineUtf16 : FoNameLayout::None;
  }
  if (event_type >= kEventFoRead && event_type <= kEventFoCleanup) {
    if (try_us()) {
      return FoNameLayout::UnicodeString;
    }
    if (try_inline()) {
      return FoNameLayout::InlineUtf16;
    }
  }
  return FoNameLayout::None;
}

[[nodiscard]] inline bool TryBindEventData(const std::byte* data,
                                           std::uint32_t* event_type,
                                           const std::byte** params,
                                           bool* uses_primary,
                                           std::size_t* type_offset_out,
                                           NotifyReadableFn readable) noexcept {
  if (data == nullptr || event_type == nullptr || params == nullptr ||
      uses_primary == nullptr || type_offset_out == nullptr ||
      readable == nullptr) {
    return false;
  }
  if (TryBindLayout(data, kEventDataTypeOffsetPrimary,
                    kEventDataParamsOffsetPrimary, event_type, params,
                    uses_primary, true, type_offset_out, readable)) {
    return true;
  }
  if (TryBindLayout(data, kEventDataTypeOffsetAlternate,
                    kEventDataParamsOffsetAlternate, event_type, params,
                    uses_primary, false, type_offset_out, readable)) {
    return true;
  }
  if (TryBindLayout(data, kEventDataTypeOffsetProcess,
                    kNotificationProcessObjectOffset, event_type, params,
                    uses_primary, true, type_offset_out, readable)) {
    return true;
  }
  if (TryBindLayout(data, kEventDataTypeOffsetProcess,
                    kEventDataParamsOffsetPrimary, event_type, params,
                    uses_primary, true, type_offset_out, readable)) {
    return true;
  }
  std::size_t type_offset = 0;
  std::uint32_t scanned = 0;
  if (!ScanSparseEventType(data, &scanned, &type_offset, readable)) {
    return false;
  }
  *event_type = scanned;
  *type_offset_out = type_offset;
  const std::byte* nearby = nullptr;
  if (NotifyReadPtr(data, type_offset + kEventDataNearbyParamsPrimary, &nearby,
                    readable)) {
    *params = nearby;
    *uses_primary = true;
    return true;
  }
  if (NotifyReadPtr(data, type_offset + kEventDataNearbyParamsAlternate,
                    &nearby, readable)) {
    *params = nearby;
    *uses_primary = false;
    return true;
  }
  *params = nullptr;
  *uses_primary = type_offset == kEventDataTypeOffsetPrimary;
  return true;
}

}  // namespace esptool::esp
