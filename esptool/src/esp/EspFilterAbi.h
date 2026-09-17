#pragma once

#include <cstddef>
#include <cstdint>
#include <limits>

namespace esptool::esp {

constexpr std::size_t kRuleEventFilterOffset = 40;
constexpr std::int32_t kFilterCtorEvent = 4;
constexpr std::size_t kRuleProcessFilterOffset = 688;
constexpr std::int32_t kFilterCtorProcess = 10;
constexpr std::int32_t kFilterCtorFileObject = 6;
constexpr std::int32_t kFilterCtorRegistryKey = 8;
constexpr std::size_t kEventObjectConfigFilterOffset = 8;
constexpr std::uint32_t kFileObjectStringPropertyMin = 1;
constexpr std::uint32_t kFileObjectStringPropertyMax = 10;

constexpr std::int32_t kStringPayloadSizeClass = 4;
static_assert(kStringPayloadSizeClass == 4, "string payload size class is 32");
constexpr std::int32_t kFilePathPayloadSizeClass = 5;
constexpr std::uint32_t kStringComparandMin = 1;
constexpr std::uint32_t kStringComparandMax = 3;
constexpr std::uint32_t kStringComparandCollection = 4;
constexpr std::uint32_t kCollectionTypeString = 2;
constexpr std::uint32_t kCollectionStringSubtype = 1;
constexpr std::uint32_t kCollectionUpdateAdd = 1;
constexpr std::int32_t kBoolPayloadSizeClass = 2;
constexpr std::uint32_t kBoolComparandEquals = 1;
constexpr std::uint32_t kBoolRhsKindImmediate = 1;
constexpr std::uint32_t kStringKindInlineUtf16 = 1;
constexpr std::uint64_t kMaxUtf16Bytes =
    std::numeric_limits<std::uint16_t>::max();

struct alignas(8) StringComparandRaw {
  std::uint32_t comparison = 0;
  std::uint32_t reserved0 = 0;
  std::uint32_t string_kind = 0;
  std::uint32_t flags = 0;
  std::uint64_t utf16_bytes = 0;
  const wchar_t* text = nullptr;
};
static_assert(sizeof(StringComparandRaw) == 32, "StringComparison raw size");
static_assert(alignof(StringComparandRaw) >= 8, "StringComparison raw align");

constexpr std::int32_t kNumericPayloadSizeClass = 3;
constexpr std::uint32_t kFileObjectNumericProperty18 = 18;
constexpr std::uint32_t kFileObjectNumericProperty28 = 28;
constexpr std::uint32_t kNumericOperatorMin = 1;
constexpr std::uint32_t kNumericOperatorMax = 11;
constexpr std::uint32_t kNumericRhsKindImmediate = 1;
constexpr std::uint64_t kFoNumericPipeTarget = 3;

struct alignas(8) NumericComparandRaw {
  std::uint32_t comparison = 0;
  std::uint32_t reserved0 = 0;
  std::uint32_t lhs_xform_count = 0;
  std::uint32_t reserved1 = 0;
  std::uint64_t lhs_xform_ptr = 0;
  std::uint32_t rhs_kind = kNumericRhsKindImmediate;
  std::uint32_t reserved2 = 0;
  std::uint32_t rhs_xform_count = 0;
  std::uint32_t reserved3 = 0;
  std::uint64_t rhs_xform_ptr = 0;
  std::uint64_t value = 0;
};
static_assert(sizeof(NumericComparandRaw) == 56, "NumericComparison raw size");
static_assert(offsetof(NumericComparandRaw, rhs_kind) == 24, "numeric +24");
static_assert(offsetof(NumericComparandRaw, value) == 48, "numeric +48");
static_assert(alignof(NumericComparandRaw) >= 8, "NumericComparison raw align");

constexpr std::int32_t kFilterCtorClient = 1;
constexpr std::int32_t kFilterCtorDesktop = 2;
constexpr std::int32_t kFilterCtorDisk = 3;
constexpr std::int32_t kFilterCtorFile = 5;
constexpr std::int32_t kFilterCtorFileStream = 7;
constexpr std::int32_t kFilterCtorRegistryKeyObject = 9;
constexpr std::int32_t kFilterCtorThread = 11;
constexpr std::int32_t kFilterCtorToken = 12;
constexpr std::int32_t kFilterCtorVolume = 13;
constexpr std::int32_t kFilterCtorPipe = 14;
constexpr std::int32_t kFilterCtorMailslot = 15;
constexpr std::int32_t kFilterCtorKtm = 16;

enum class LeafPayloadKind { None, String, Numeric, Bool };

struct alignas(8) BoolComparandRaw {
  std::uint32_t comparison = kBoolComparandEquals;
  std::uint32_t rhs_kind = kBoolRhsKindImmediate;
  std::uint32_t value = 0;
  std::uint32_t reserved = 0;
};
static_assert(sizeof(BoolComparandRaw) == 16, "BoolComparison raw size");
static_assert(alignof(BoolComparandRaw) >= 8, "BoolComparison raw align");

constexpr std::uint32_t kFilePathWrapperKind = 1;

struct alignas(8) FilePathComparandRaw {
  std::uint32_t kind = kFilePathWrapperKind;
  std::uint32_t reserved = 0;
  StringComparandRaw string{};
};
static_assert(sizeof(FilePathComparandRaw) == 40, "File property 17 wrapper");
static_assert(offsetof(FilePathComparandRaw, string) == 8,
              "StringComparison at +8");

struct alignas(8) CollectionComparandRaw {
  std::uint32_t comparison = kStringComparandCollection;
  std::uint32_t reserved = 0;
  void* collection = nullptr;
  std::uint64_t pad16 = 0;
  std::uint64_t pad24 = 0;
};
static_assert(sizeof(CollectionComparandRaw) == 32, "collection comparand 32");
static_assert(offsetof(CollectionComparandRaw, collection) == 8,
              "collection handle at +8");

struct alignas(8) CollectionUpdateEntry {
  std::uint32_t operation = kCollectionUpdateAdd;
  std::uint32_t pad0 = 0;
  std::uint16_t utf16_bytes = 0;
  std::uint16_t pad1 = 0;
  std::uint32_t pad2 = 0;
  const wchar_t* text = nullptr;
};
static_assert(sizeof(CollectionUpdateEntry) == 24, "update entry stride 24");
static_assert(offsetof(CollectionUpdateEntry, utf16_bytes) == 8,
              "string length at +8");
static_assert(offsetof(CollectionUpdateEntry, text) == 16, "string ptr at +16");

struct alignas(8) CollectionIntegerUpdateEntry {
  std::uint32_t operation = kCollectionUpdateAdd;
  std::uint32_t pad0 = 0;
  std::int64_t value = 0;
  std::uint64_t pad16 = 0;
};
static_assert(sizeof(CollectionIntegerUpdateEntry) == 24,
              "integer update entry 24");
static_assert(offsetof(CollectionIntegerUpdateEntry, value) == 8,
              "integer payload at +8");

struct alignas(8) CollectionBinaryUpdateEntry {
  std::uint32_t operation = kCollectionUpdateAdd;
  std::uint32_t pad0 = 0;
  std::uint32_t byte_count = 0;
  std::uint32_t pad1 = 0;
  const void* data = nullptr;
};
static_assert(sizeof(CollectionBinaryUpdateEntry) == 24,
              "binary update entry 24");
static_assert(offsetof(CollectionBinaryUpdateEntry, byte_count) == 8,
              "binary length at +8");
static_assert(offsetof(CollectionBinaryUpdateEntry, data) == 16,
              "binary ptr at +16");

[[nodiscard]] constexpr std::uint32_t PropertyCeiling(
    std::int32_t constructor) noexcept {
  switch (constructor) {
    case kFilterCtorClient:
    case kFilterCtorDesktop:
      return 1;
    case kFilterCtorRegistryKeyObject:
    case kFilterCtorPipe:
    case kFilterCtorMailslot:
      return 2;
    case kFilterCtorEvent:
    case kFilterCtorKtm:
      return 3;
    case kFilterCtorFileStream:
    case kFilterCtorRegistryKey:
      return 4;
    case kFilterCtorThread:
      return 11;
    case kFilterCtorToken:
      return 12;
    case kFilterCtorDisk:
      return 13;
    case kFilterCtorVolume:
      return 16;
    case kFilterCtorFile:
      return 18;
    case kFilterCtorProcess:
      return 23;
    case kFilterCtorFileObject:
      return 28;
    default:
      return 0;
  }
}

[[nodiscard]] constexpr LeafPayloadKind LeafPayload(
    std::int32_t constructor, std::uint32_t property) noexcept {
  if (property == 0 || property > PropertyCeiling(constructor)) {
    return LeafPayloadKind::None;
  }
  if (constructor == kFilterCtorClient && property == 1) {
    return LeafPayloadKind::Bool;
  }
  if (constructor == kFilterCtorEvent && property == 1) {
    return LeafPayloadKind::Bool;
  }
  if (constructor == kFilterCtorEvent && property == 2) {
    return LeafPayloadKind::Numeric;
  }
  if (constructor == kFilterCtorFile && property == 17) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorFile && property == 2) {
    return LeafPayloadKind::Numeric;
  }
  if (constructor == kFilterCtorFileObject &&
      property >= kFileObjectStringPropertyMin &&
      property <= kFileObjectStringPropertyMax) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorFileObject &&
      (property == kFileObjectNumericProperty18 ||
       property == kFileObjectNumericProperty28)) {
    return LeafPayloadKind::Numeric;
  }
  if (constructor == kFilterCtorFileStream && property == 1) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorRegistryKey &&
      (property == 1 || property == 2)) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorRegistryKeyObject && property == 1) {
    return LeafPayloadKind::Bool;
  }
  if (constructor == kFilterCtorRegistryKeyObject && property == 2) {
    return LeafPayloadKind::Numeric;
  }
  if (constructor == kFilterCtorProcess && property == 1) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorThread && property == 1) {
    return LeafPayloadKind::Numeric;
  }
  if (constructor == kFilterCtorToken && property == 3) {
    return LeafPayloadKind::Numeric;
  }
  if ((constructor == kFilterCtorDesktop || constructor == kFilterCtorDisk ||
       constructor == kFilterCtorVolume || constructor == kFilterCtorPipe ||
       constructor == kFilterCtorMailslot) &&
      property == 1) {
    return LeafPayloadKind::String;
  }
  if (constructor == kFilterCtorKtm && property == 2) {
    return LeafPayloadKind::Numeric;
  }
  return LeafPayloadKind::None;
}

[[nodiscard]] constexpr bool IsObservedStringProperty(
    std::int32_t constructor, std::uint32_t property) noexcept {
  return LeafPayload(constructor, property) == LeafPayloadKind::String;
}

[[nodiscard]] constexpr bool IsObservedNumericProperty(
    std::int32_t constructor, std::uint32_t property) noexcept {
  return LeafPayload(constructor, property) == LeafPayloadKind::Numeric;
}

[[nodiscard]] constexpr bool IsObservedBoolProperty(
    std::int32_t constructor, std::uint32_t property) noexcept {
  return LeafPayload(constructor, property) == LeafPayloadKind::Bool;
}

}  // namespace esptool::esp
