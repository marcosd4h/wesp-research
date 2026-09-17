#include <doctest.h>

#include "esp/EspNotifyDecode.h"
#include "esp/EspMemoryView.h"
#include "esp/EspNotifyAbi.h"
#include "esp/EspEventIds.h"

#include <cstddef>
#include <cstdint>
#include <vector>

namespace {

const std::byte* g_begin = nullptr;
const std::byte* g_end = nullptr;

[[nodiscard]] bool VectorReadable(const std::byte* pointer,
                                  std::size_t size) noexcept {
  if (pointer == nullptr || size == 0 || g_begin == nullptr) {
    return false;
  }
  const auto* const last = pointer + size;
  return pointer >= g_begin && last <= g_end && last >= pointer;
}

[[nodiscard]] std::vector<std::byte> MakeZeroedBlob() {
  return std::vector<std::byte>(1024, std::byte{0});
}

void BindBlob(const std::vector<std::byte>& blob) noexcept {
  g_begin = blob.data();
  g_end = blob.data() + blob.size();
}

void WriteBoxedU32(void* base, std::size_t offset, std::uint32_t type,
                   std::uint32_t payload) noexcept {
  esptool::esp::WriteU32At(base, offset + esptool::esp::kBoxedTypeOffset, type);
  esptool::esp::WriteU32At(base, offset + esptool::esp::kBoxedPayloadOffset,
                           payload);
}

void WriteQueryBag(void* base, std::size_t bag_offset, std::size_t bag_at,
                   std::size_t boxed_at, std::uint32_t count,
                   std::uint32_t boxed_type, std::uint32_t payload) noexcept {
  esptool::esp::WritePtrAt(base, bag_offset,
                           static_cast<std::uint8_t*>(base) + bag_at);
  esptool::esp::WriteU32At(base, bag_at + esptool::esp::kObjectQueryCountOffset,
                           count);
  esptool::esp::WritePtrAt(base, bag_at + esptool::esp::kObjectQueryPtrOffset,
                           static_cast<std::uint8_t*>(base) + boxed_at);
  WriteBoxedU32(base, boxed_at, boxed_type, payload);
}

}  // namespace

TEST_CASE("TryUnboxU32 rejects nulls and type mismatch") {
  using esptool::esp::TryUnboxU32;
  using esptool::esp::kBoxedTypeInt32;
  using esptool::esp::kBoxedTypeU32;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteBoxedU32(blob.data(), 0, kBoxedTypeInt32, 99);

  std::uint32_t out = 0;
  CHECK_FALSE(TryUnboxU32(nullptr, kBoxedTypeU32, &out, VectorReadable));
  CHECK_FALSE(TryUnboxU32(blob.data(), kBoxedTypeU32, nullptr, VectorReadable));
  CHECK_FALSE(TryUnboxU32(blob.data(), kBoxedTypeU32, &out, VectorReadable));
}

TEST_CASE("TryUnboxU32 reads matching kBoxedTypeU32 payload") {
  using esptool::esp::TryUnboxU32;
  using esptool::esp::kBoxedTypeU32;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteBoxedU32(blob.data(), 0, kBoxedTypeU32, 0x11223344u);

  std::uint32_t out = 0;
  REQUIRE(TryUnboxU32(blob.data(), kBoxedTypeU32, &out, VectorReadable));
  CHECK(out == 0x11223344u);
}

TEST_CASE("TryUnboxPid accepts boxed u32, boxed int32, and property tag") {
  using esptool::esp::TryUnboxPid;
  using esptool::esp::WriteU32At;
  using esptool::esp::kBoxedTypeInt32;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kPropertyValueTagU32;
  using esptool::esp::kPropertyValueU32Offset;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);

  WriteBoxedU32(blob.data(), 0, kBoxedTypeU32, 1001);
  std::uint32_t pid = 0;
  REQUIRE(TryUnboxPid(blob.data(), &pid, VectorReadable));
  CHECK(pid == 1001u);

  WriteBoxedU32(blob.data(), 0, kBoxedTypeInt32, 2002);
  REQUIRE(TryUnboxPid(blob.data(), &pid, VectorReadable));
  CHECK(pid == 2002u);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  blob[0] = static_cast<std::byte>(kPropertyValueTagU32);
  WriteU32At(blob.data(), kPropertyValueU32Offset, 3003u);
  REQUIRE(TryUnboxPid(blob.data(), &pid, VectorReadable));
  CHECK(pid == 3003u);
}

TEST_CASE("IsNameBoxedType is true only for 7 and 8") {
  using esptool::esp::IsNameBoxedType;
  using esptool::esp::kBoxedTypeInt32;
  using esptool::esp::kBoxedTypeInt64;
  using esptool::esp::kBoxedTypePathString;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kBoxedTypeUnicodeString;

  CHECK(IsNameBoxedType(kBoxedTypePathString));
  CHECK(IsNameBoxedType(kBoxedTypeUnicodeString));
  CHECK(IsNameBoxedType(7));
  CHECK(IsNameBoxedType(8));
  CHECK_FALSE(IsNameBoxedType(0));
  CHECK_FALSE(IsNameBoxedType(kBoxedTypeU32));
  CHECK_FALSE(IsNameBoxedType(kBoxedTypeInt32));
  CHECK_FALSE(IsNameBoxedType(kBoxedTypeInt64));
  CHECK_FALSE(IsNameBoxedType(9));
}

TEST_CASE("TryReadQueryBagU32 walks a synthetic bag") {
  using esptool::esp::TryReadQueryBagU32;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kParamsPidBagOffset;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteQueryBag(blob.data(), kParamsPidBagOffset, 64, 128, 1, kBoxedTypeU32,
                4242u);

  std::uint32_t value = 0;
  REQUIRE(TryReadQueryBagU32(blob.data(), kParamsPidBagOffset, 1, &value,
                             VectorReadable));
  CHECK(value == 4242u);
  CHECK_FALSE(TryReadQueryBagU32(blob.data(), kParamsPidBagOffset, 2, &value,
                                 VectorReadable));
}

TEST_CASE("TryReadPidTidFromParams reads synthetic pid and tid bags") {
  using esptool::esp::TryReadPidTidFromParams;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kParamsPidBagOffset;
  using esptool::esp::kParamsTidBagOffset;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteQueryBag(blob.data(), kParamsPidBagOffset, 64, 128, 1, kBoxedTypeU32,
                111u);
  WriteQueryBag(blob.data(), kParamsTidBagOffset, 192, 256, 1, kBoxedTypeU32,
                222u);

  std::uint32_t pid = 0;
  std::uint32_t tid = 0;
  REQUIRE(TryReadPidTidFromParams(blob.data(), &pid, &tid, VectorReadable));
  CHECK(pid == 111u);
  CHECK(tid == 222u);

  CHECK_FALSE(
      TryReadPidTidFromParams(nullptr, &pid, &tid, VectorReadable));
  CHECK_FALSE(
      TryReadPidTidFromParams(blob.data(), nullptr, &tid, VectorReadable));
  CHECK_FALSE(
      TryReadPidTidFromParams(blob.data(), &pid, nullptr, VectorReadable));
  CHECK_FALSE(TryReadPidTidFromParams(blob.data(), &pid, &tid, nullptr));
}

TEST_CASE("FindQuerySlot and notification query helpers") {
  using esptool::esp::FindQuerySlot;
  using esptool::esp::NotifyReadU32;
  using esptool::esp::TryReadNotificationQueryPid;
  using esptool::esp::TryReadNotificationQuerySlot;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kNotificationQueryCountMax;
  using esptool::esp::kNotificationQueryCountOffset;
  using esptool::esp::kNotificationQueryPtrOffset;
  using esptool::esp::kProcessQueryPropertyName;
  using esptool::esp::kProcessQueryPropertyPid;
  using esptool::esp::kQuerySlotPropertyOffset;
  using esptool::esp::kQuerySlotStride;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  constexpr std::size_t kArrayAt = 320;
  WriteU32At(blob.data(), kNotificationQueryCountOffset, 2);
  WritePtrAt(blob.data(), kNotificationQueryPtrOffset, blob.data() + kArrayAt);
  WriteU32At(blob.data(), kArrayAt + kQuerySlotPropertyOffset,
             kProcessQueryPropertyName);
  WriteBoxedU32(blob.data(), kArrayAt, kBoxedTypeU32, 1);
  WriteU32At(blob.data(), kArrayAt + kQuerySlotStride + kQuerySlotPropertyOffset,
             kProcessQueryPropertyPid);
  WriteBoxedU32(blob.data(), kArrayAt + kQuerySlotStride, kBoxedTypeU32, 4321u);

  const std::byte* slot = nullptr;
  const auto match_pid = [](const std::byte* cursor,
                            esptool::esp::NotifyReadableFn can_read) noexcept {
    std::uint32_t property = 0;
    return NotifyReadU32(cursor, kQuerySlotPropertyOffset, &property,
                         can_read) &&
           property == kProcessQueryPropertyPid;
  };
  REQUIRE(FindQuerySlot(blob.data(), &slot, VectorReadable, match_pid));
  CHECK(slot == blob.data() + kArrayAt + kQuerySlotStride);

  const auto match_missing =
      [](const std::byte* cursor,
         esptool::esp::NotifyReadableFn can_read) noexcept {
        std::uint32_t property = 0;
        return NotifyReadU32(cursor, kQuerySlotPropertyOffset, &property,
                             can_read) &&
               property == 99u;
      };
  CHECK_FALSE(
      FindQuerySlot(blob.data(), &slot, VectorReadable, match_missing));

  REQUIRE(TryReadNotificationQuerySlot(blob.data(), kProcessQueryPropertyPid,
                                       &slot, VectorReadable));
  CHECK(slot == blob.data() + kArrayAt + kQuerySlotStride);
  CHECK_FALSE(TryReadNotificationQuerySlot(blob.data(), 99u, &slot,
                                           VectorReadable));

  std::uint32_t pid = 0;
  REQUIRE(TryReadNotificationQueryPid(blob.data(), &pid, VectorReadable));
  CHECK(pid == 4321u);

  WriteU32At(blob.data(), kNotificationQueryCountOffset, 0);
  CHECK_FALSE(
      FindQuerySlot(blob.data(), &slot, VectorReadable, match_pid));
  CHECK_FALSE(TryReadNotificationQuerySlot(blob.data(), kProcessQueryPropertyPid,
                                           &slot, VectorReadable));

  WriteU32At(blob.data(), kNotificationQueryCountOffset,
             kNotificationQueryCountMax + 1);
  CHECK_FALSE(
      FindQuerySlot(blob.data(), &slot, VectorReadable, match_pid));
  CHECK_FALSE(TryReadNotificationQueryPid(blob.data(), &pid, VectorReadable));

  CHECK_FALSE(FindQuerySlot(nullptr, &slot, VectorReadable, match_pid));
  CHECK_FALSE(FindQuerySlot(blob.data(), nullptr, VectorReadable, match_pid));
  CHECK_FALSE(FindQuerySlot(blob.data(), &slot, nullptr, match_pid));
}

TEST_CASE("TryReadNotificationQueryNameSlot finds a path-string slot") {
  using esptool::esp::TryReadNotificationQueryNameSlot;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;
  using esptool::esp::kBoxedTypePathString;
  using esptool::esp::kNotificationQueryCountOffset;
  using esptool::esp::kNotificationQueryPtrOffset;
  using esptool::esp::kQuerySlotPropertyOffset;
  using esptool::esp::kQuerySlotStride;
  using esptool::esp::kQuerySlotTypeOffset;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  constexpr std::size_t kArrayAt = 640;
  WriteU32At(blob.data(), kNotificationQueryCountOffset, 1);
  WritePtrAt(blob.data(), kNotificationQueryPtrOffset, blob.data() + kArrayAt);
  WriteU32At(blob.data(), kArrayAt + kQuerySlotPropertyOffset, 1);
  WriteU32At(blob.data(), kArrayAt + kQuerySlotTypeOffset, kBoxedTypePathString);

  const std::byte* slot = nullptr;
  REQUIRE(TryReadNotificationQueryNameSlot(blob.data(), &slot, VectorReadable));
  CHECK(slot == blob.data() + kArrayAt);
}

TEST_CASE("ScanSparseEventType finds 1000 and skips 12, 30, and threads") {
  using esptool::esp::ScanSparseEventType;
  using esptool::esp::WriteU32At;
  using esptool::esp::kEventFoOpen;
  using esptool::esp::kEventPipeCreate;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventThreadCreate;
  using esptool::esp::kEventThreadStart;
  using esptool::esp::kEventThreadTerminate;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteU32At(blob.data(), 0, 12u);
  WriteU32At(blob.data(), 4, 30u);
  WriteU32At(blob.data(), 8, kEventThreadCreate);
  WriteU32At(blob.data(), 12, kEventProcessCreate);

  std::uint32_t event_type = 0;
  std::size_t type_offset = 0;
  REQUIRE(ScanSparseEventType(blob.data(), &event_type, &type_offset,
                              VectorReadable));
  CHECK(event_type == kEventProcessCreate);
  CHECK(type_offset == 12);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteU32At(blob.data(), 0, 12u);
  WriteU32At(blob.data(), 4, 30u);
  CHECK_FALSE(ScanSparseEventType(blob.data(), &event_type, &type_offset,
                                  VectorReadable));

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteU32At(blob.data(), 0, kEventThreadCreate);
  WriteU32At(blob.data(), 4, kEventThreadStart);
  WriteU32At(blob.data(), 8, kEventThreadTerminate);
  CHECK_FALSE(ScanSparseEventType(blob.data(), &event_type, &type_offset,
                                  VectorReadable));

  WriteU32At(blob.data(), 12, kEventFoOpen);
  REQUIRE(ScanSparseEventType(blob.data(), &event_type, &type_offset,
                              VectorReadable));
  CHECK(event_type == kEventFoOpen);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteU32At(blob.data(), 0, kEventThreadCreate);
  WriteU32At(blob.data(), 4, kEventPipeCreate);
  REQUIRE(ScanSparseEventType(blob.data(), &event_type, &type_offset,
                              VectorReadable));
  CHECK(event_type == kEventPipeCreate);
}

TEST_CASE("TryBindLayout and TryBindEventData bind documented offsets") {
  using esptool::esp::TryBindEventData;
  using esptool::esp::TryBindLayout;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;
  using esptool::esp::kEventDataParamsOffsetAlternate;
  using esptool::esp::kEventDataParamsOffsetPrimary;
  using esptool::esp::kEventDataTypeOffsetAlternate;
  using esptool::esp::kEventDataTypeOffsetPrimary;
  using esptool::esp::kEventDataTypeOffsetProcess;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventProcessTerminate;
  using esptool::esp::kNotificationProcessObjectOffset;

  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  WriteU32At(blob.data(), kEventDataTypeOffsetPrimary, kEventProcessCreate);
  WritePtrAt(blob.data(), kEventDataParamsOffsetPrimary, blob.data() + 400);

  std::uint32_t event_type = 0;
  const std::byte* params = nullptr;
  bool uses_primary = false;
  std::size_t type_offset = 0;
  REQUIRE(TryBindLayout(blob.data(), kEventDataTypeOffsetPrimary,
                        kEventDataParamsOffsetPrimary, &event_type, &params,
                        &uses_primary, true, &type_offset, VectorReadable));
  CHECK(event_type == kEventProcessCreate);
  CHECK(params == blob.data() + 400);
  CHECK(uses_primary);
  CHECK(type_offset == kEventDataTypeOffsetPrimary);

  REQUIRE(TryBindEventData(blob.data(), &event_type, &params, &uses_primary,
                           &type_offset, VectorReadable));
  CHECK(event_type == kEventProcessCreate);
  CHECK(params == blob.data() + 400);
  CHECK(uses_primary);
  CHECK(type_offset == 120);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteU32At(blob.data(), kEventDataTypeOffsetAlternate, kEventProcessTerminate);
  WritePtrAt(blob.data(), kEventDataParamsOffsetAlternate, blob.data() + 400);
  REQUIRE(TryBindLayout(blob.data(), kEventDataTypeOffsetAlternate,
                        kEventDataParamsOffsetAlternate, &event_type, &params,
                        &uses_primary, false, &type_offset, VectorReadable));
  CHECK(event_type == kEventProcessTerminate);
  CHECK_FALSE(uses_primary);
  CHECK(type_offset == kEventDataTypeOffsetAlternate);

  REQUIRE(TryBindEventData(blob.data(), &event_type, &params, &uses_primary,
                           &type_offset, VectorReadable));
  CHECK(event_type == kEventProcessTerminate);
  CHECK(params == blob.data() + 400);
  CHECK_FALSE(uses_primary);
  CHECK(type_offset == 136);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteU32At(blob.data(), kEventDataTypeOffsetProcess, kEventProcessCreate);
  WritePtrAt(blob.data(), kNotificationProcessObjectOffset, blob.data() + 400);
  REQUIRE(TryBindEventData(blob.data(), &event_type, &params, &uses_primary,
                           &type_offset, VectorReadable));
  CHECK(event_type == kEventProcessCreate);
  CHECK(params == blob.data() + 400);
  CHECK(uses_primary);
  CHECK(type_offset == 224);

  CHECK_FALSE(TryBindEventData(nullptr, &event_type, &params, &uses_primary,
                               &type_offset, VectorReadable));
  CHECK_FALSE(TryBindEventData(blob.data(), nullptr, &params, &uses_primary,
                               &type_offset, VectorReadable));
  CHECK_FALSE(TryBindEventData(blob.data(), &event_type, nullptr, &uses_primary,
                               &type_offset, VectorReadable));
  CHECK_FALSE(TryBindEventData(blob.data(), &event_type, &params, nullptr,
                               &type_offset, VectorReadable));
  CHECK_FALSE(TryBindEventData(blob.data(), &event_type, &params, &uses_primary,
                               nullptr, VectorReadable));
  CHECK_FALSE(TryBindEventData(blob.data(), &event_type, &params, &uses_primary,
                               &type_offset, nullptr));
  CHECK_FALSE(TryBindLayout(nullptr, kEventDataTypeOffsetPrimary,
                            kEventDataParamsOffsetPrimary, &event_type, &params,
                            &uses_primary, true, &type_offset, VectorReadable));
  CHECK_FALSE(TryBindLayout(blob.data(), kEventDataTypeOffsetPrimary,
                            kEventDataParamsOffsetPrimary, &event_type, &params,
                            &uses_primary, true, &type_offset, nullptr));
}

TEST_CASE("ClassifyFoNotificationName layouts for create, open, and read") {
  using esptool::esp::ClassifyFoNotificationName;
  using esptool::esp::FoNameLayout;
  using esptool::esp::WriteBytesAt;
  using esptool::esp::WritePtrAt;
  using esptool::esp::kEventFoCreate;
  using esptool::esp::kEventFoOpen;
  using esptool::esp::kEventFoRead;
  using esptool::esp::kFoNotificationInlineNameOffset;
  using esptool::esp::kFoNotificationNameUsOffset;
  using esptool::esp::kNtPathFirstWchar;
  using esptool::esp::kUnicodeStringBufferOffset;
  using esptool::esp::kUnicodeStringLengthOffset;

  const std::byte* source = nullptr;
  CHECK(ClassifyFoNotificationName(kEventFoCreate, nullptr, &source,
                                   VectorReadable) == FoNameLayout::None);
  auto blob = MakeZeroedBlob();
  BindBlob(blob);
  CHECK(ClassifyFoNotificationName(kEventFoCreate, blob.data(), nullptr,
                                   VectorReadable) == FoNameLayout::None);
  CHECK(ClassifyFoNotificationName(kEventFoCreate, blob.data(), &source,
                                   nullptr) == FoNameLayout::None);

  constexpr std::size_t kNameBuffer = 800;
  WriteBytesAt(blob.data(), kFoNotificationNameUsOffset + kUnicodeStringLengthOffset,
               static_cast<std::uint16_t>(4));
  WritePtrAt(blob.data(),
             kFoNotificationNameUsOffset + kUnicodeStringBufferOffset,
             blob.data() + kNameBuffer);
  WriteBytesAt(blob.data(), kNameBuffer, kNtPathFirstWchar);
  REQUIRE(ClassifyFoNotificationName(kEventFoCreate, blob.data(), &source,
                                     VectorReadable) ==
          FoNameLayout::UnicodeString);
  CHECK(source == blob.data() + kFoNotificationNameUsOffset);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteBytesAt(blob.data(), kFoNotificationInlineNameOffset, kNtPathFirstWchar);
  REQUIRE(ClassifyFoNotificationName(kEventFoOpen, blob.data(), &source,
                                     VectorReadable) ==
          FoNameLayout::InlineUtf16);
  CHECK(source == blob.data() + kFoNotificationInlineNameOffset);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteBytesAt(blob.data(), kFoNotificationNameUsOffset + kUnicodeStringLengthOffset,
               static_cast<std::uint16_t>(4));
  WritePtrAt(blob.data(),
             kFoNotificationNameUsOffset + kUnicodeStringBufferOffset,
             blob.data() + kNameBuffer);
  WriteBytesAt(blob.data(), kNameBuffer, kNtPathFirstWchar);
  REQUIRE(ClassifyFoNotificationName(kEventFoRead, blob.data(), &source,
                                     VectorReadable) ==
          FoNameLayout::UnicodeString);
  CHECK(source == blob.data() + kFoNotificationNameUsOffset);

  blob.assign(blob.size(), std::byte{0});
  BindBlob(blob);
  WriteBytesAt(blob.data(), kFoNotificationInlineNameOffset, kNtPathFirstWchar);
  REQUIRE(ClassifyFoNotificationName(kEventFoRead, blob.data(), &source,
                                     VectorReadable) ==
          FoNameLayout::InlineUtf16);
  CHECK(source == blob.data() + kFoNotificationInlineNameOffset);
}
