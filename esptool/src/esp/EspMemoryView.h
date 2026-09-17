#pragma once

#include <bit>
#include <cstddef>
#include <cstdint>
#include <cstring>

#include "esp/EspCore.h"

namespace esptool::esp {

using NotifyReadableFn = bool (*)(const std::byte* pointer,
                                  std::size_t size) noexcept;

[[nodiscard]] inline bool NotifyAlwaysReadable(const std::byte* pointer,
                                               std::size_t size) noexcept {
  return pointer != nullptr && size != 0;
}

template <typename T>
[[nodiscard]] inline bool ReadPod(const std::byte* base, std::size_t offset,
                                  T* out, NotifyReadableFn readable) noexcept {
  if (base == nullptr || out == nullptr || readable == nullptr) {
    return false;
  }
  const auto* source = base + offset;
  if (!readable(source, sizeof(T))) {
    return false;
  }
  std::memcpy(out, source, sizeof(T));
  return true;
}

[[nodiscard]] inline bool NotifyReadU16(const std::byte* base,
                                        std::size_t offset, std::uint16_t* out,
                                        NotifyReadableFn readable) noexcept {
  return ReadPod(base, offset, out, readable);
}

[[nodiscard]] inline bool NotifyReadU32(const std::byte* base,
                                        std::size_t offset, std::uint32_t* out,
                                        NotifyReadableFn readable) noexcept {
  return ReadPod(base, offset, out, readable);
}

[[nodiscard]] inline bool NotifyReadPtr(const std::byte* base,
                                        std::size_t offset,
                                        const std::byte** out,
                                        NotifyReadableFn readable) noexcept {
  std::uint64_t value = 0;
  if (!ReadPod(base, offset, &value, readable)) {
    return false;
  }
  *out = std::bit_cast<const std::byte*>(value);
  return *out != nullptr;
}

[[nodiscard]] inline const std::byte* AtOffset(const std::byte* base,
                                               std::size_t offset) noexcept {
  return base + offset;
}

[[nodiscard]] inline const std::byte* QuerySlotAt(const std::byte* array,
                                                  std::uint32_t index,
                                                  std::size_t stride) noexcept {
  return AtOffset(array, static_cast<std::size_t>(index) * stride);
}

inline void WriteU32At(void* bytes, std::size_t offset,
                       std::uint32_t value) noexcept {
  std::memcpy(static_cast<std::uint8_t*>(bytes) + offset, &value,
              sizeof(value));
}

inline void WritePtrAt(void* bytes, std::size_t offset,
                       const void* value) noexcept {
  std::memcpy(static_cast<std::uint8_t*>(bytes) + offset, &value,
              sizeof(value));
}

template <typename Tag>
inline void WritePtrAt(void* bytes, std::size_t offset,
                       Opaque<Tag> object) noexcept {
  WritePtrAt(bytes, offset, object.get());
}

template <typename T>
inline void WriteBytesAt(void* base, std::size_t offset,
                         const T& value) noexcept {
  std::memcpy(static_cast<std::uint8_t*>(base) + offset, &value, sizeof(value));
}

}  // namespace esptool::esp
