#pragma once

#include <array>
#include <cstddef>
#include <cstdint>

namespace esptool::esp {

constexpr std::size_t kNotificationQueueIdOffset = 0;
constexpr std::size_t kNotificationKindOffset = 8;
constexpr std::size_t kNotificationDataPtrOffset = 16;
constexpr std::size_t kNotificationOverlappedPtrOffset = 24;
constexpr std::size_t kNotificationInternalHighPtrOffset = 32;
constexpr std::size_t kNotificationIdentifierOffset = 64;
constexpr std::size_t kNotificationPayloadLengthOffset = 72;

inline constexpr std::array kNotificationDataCandidates{
    kNotificationDataPtrOffset,
    kNotificationKindOffset,
    kNotificationOverlappedPtrOffset,
    kNotificationInternalHighPtrOffset,
};

constexpr std::size_t kEventDataTypeOffsetPrimary = 120;
constexpr std::size_t kEventDataParamsOffsetPrimary = 160;
constexpr std::size_t kEventDataTypeOffsetAlternate = 136;
constexpr std::size_t kEventDataParamsOffsetAlternate = 192;
static_assert(kEventDataTypeOffsetPrimary == 120);
static_assert(kEventDataParamsOffsetPrimary == 160);
static_assert(kEventDataTypeOffsetAlternate == 136);
static_assert(kEventDataParamsOffsetAlternate == 192);

constexpr std::size_t kEventDataThreadObjectOffset = 32;
constexpr std::size_t kEventDataProcessObjectOffset = 72;
constexpr std::size_t kNotificationProcessObjectOffset = 80;

constexpr std::size_t kParamsObjectOffset = 24;
constexpr std::size_t kFoTypeOffsetPrimary = 32;
constexpr std::uint32_t kFoTypePipePrimary = 3;
constexpr std::size_t kFoTypeOffsetAlternate = 40;
constexpr std::uint32_t kFoTypePipeAlternate = 12;
static_assert(kFoTypeOffsetPrimary == 32);
static_assert(kFoTypePipePrimary == 3);
static_assert(kFoTypeOffsetAlternate == 40);
static_assert(kFoTypePipeAlternate == 12);

constexpr std::size_t kNameCollectionOffset = 40;
constexpr std::size_t kNameCollectionCountOffset = 8;
constexpr std::size_t kNameBoxedOffset = 16;
constexpr std::size_t kBoxedTypeOffset = 4;
constexpr std::size_t kPropertyValueTagOffset = 0;
constexpr std::size_t kPropertyValueU32Offset = 4;
constexpr std::uint32_t kBoxedTypeU32 = 4;
constexpr std::uint32_t kBoxedTypeInt32 = 5;
constexpr std::uint32_t kBoxedTypePathString = 7;
constexpr std::uint32_t kBoxedTypeUnicodeString = 8;
constexpr std::uint32_t kBoxedTypeInt64 = 10;
constexpr std::uint32_t kPropertyValueTagU32 = 4;
constexpr std::uint32_t kPropertyValueTagPath = 7;
constexpr std::size_t kBoxedPayloadOffset = 8;
constexpr std::size_t kEventDataTypeOffsetProcess = 224;
static_assert(kEventDataTypeOffsetProcess == 0xE0);
// ProcessCreate type is at notification +0xE0. Include-query results
// follow: count at +0x120, array pointer at +0x128. Each slot is
// {property, type, payload} (16 bytes). +0x50 is a queue activity
// object, not a process object.
constexpr std::size_t kNotificationQueryCountOffset = 0x120;
constexpr std::size_t kNotificationQueryPtrOffset = 0x128;
constexpr std::size_t kQuerySlotPropertyOffset = 0;
constexpr std::size_t kQuerySlotTypeOffset = 4;
constexpr std::size_t kQuerySlotPayloadOffset = 8;
constexpr std::size_t kQuerySlotStride = 16;
constexpr std::uint32_t kProcessQueryPropertyPid = 6;
constexpr std::uint32_t kProcessQueryPropertyName = 1;
constexpr std::uint32_t kNotificationQueryCountMax = 16;
static_assert(kNotificationQueryCountOffset == 288);
static_assert(kNotificationQueryPtrOffset == 296);
static_assert(kQuerySlotStride == 16);
static_assert(kProcessQueryPropertyPid == 6);
constexpr std::size_t kUnicodeStringLengthOffset = 0;
constexpr std::size_t kUnicodeStringBufferOffset = 8;
constexpr std::size_t kNameWrapperInnerOffsetAlternate = 48;
constexpr std::size_t kWrapperStatusOffset = 16;
constexpr std::size_t kWrapperBlobOffset = 8;
constexpr std::size_t kParamsPidBagOffset = 16;
constexpr std::size_t kParamsTidBagOffset = 8;
constexpr std::size_t kProcessObjectQueryBagOffset = 16;
inline constexpr std::array<std::size_t, 9> kProcessPidBagCandidates{
    kParamsPidBagOffset, 0, 24, 32, 40, 48, 72, 216, 632,
};
constexpr std::size_t kProcessCreateChildObjectOffset = 216;
constexpr std::size_t kProcessCreateActorObjectOffset = 632;
static_assert(kParamsPidBagOffset == 16);
static_assert(kParamsTidBagOffset == 8);
constexpr std::size_t kObjectQueryCountOffset = 8;
constexpr std::size_t kObjectQueryPtrOffset = 16;
constexpr std::size_t kPropertyCollectionStride = 16;
constexpr std::uint32_t kProcessQueryCountRequired = 3;
constexpr std::uint32_t kProcessQueryNameIndex = 3;
constexpr std::size_t kPipeCreatePidOffset = 72;
constexpr std::size_t kPipeCreateTidOffset = 76;
constexpr std::size_t kFoOpenPidOffset = 48;
constexpr std::size_t kFoOpenTidOffset = 52;
// FoCreate 2000: UNICODE_STRING at +0x238 (Buffer at +0x248).
// FoOpen 2001: pointer at +0x230 to inline UTF-16 at +0x238.
constexpr std::size_t kFoNotificationNamePtrOffset = 0x230;
constexpr std::size_t kFoNotificationNameUsOffset = 0x238;
constexpr std::size_t kFoNotificationInlineNameOffset = 0x238;
constexpr std::uint16_t kNtPathFirstWchar = 0x005C;
static_assert(kFoNotificationNamePtrOffset == 560);
static_assert(kFoNotificationNameUsOffset == 568);
static_assert(kNtPathFirstWchar == 0x5C);

constexpr std::size_t kEventDataScanLimit = 256;
constexpr std::size_t kEventDataNearbyParamsPrimary = 40;
constexpr std::size_t kEventDataNearbyParamsAlternate = 56;

}  // namespace esptool::esp
