#include <doctest.h>

#include "esp/EspMemoryView.h"

#include <bit>
#include <cstdint>
#include <cstring>

namespace {

bool NeverReadable(const std::byte*, std::size_t) noexcept { return false; }

}  // namespace

TEST_CASE("NotifyAlwaysReadable rejects null or zero size") {
  using esptool::esp::NotifyAlwaysReadable;

  std::byte cell{};
  CHECK_FALSE(NotifyAlwaysReadable(nullptr, 1));
  CHECK_FALSE(NotifyAlwaysReadable(nullptr, 0));
  CHECK_FALSE(NotifyAlwaysReadable(&cell, 0));
  CHECK(NotifyAlwaysReadable(&cell, 1));
}

TEST_CASE("ReadPod and NotifyRead* succeed on a stack buffer") {
  using esptool::esp::NotifyAlwaysReadable;
  using esptool::esp::NotifyReadPtr;
  using esptool::esp::NotifyReadU16;
  using esptool::esp::NotifyReadU32;
  using esptool::esp::ReadPod;
  using esptool::esp::WriteBytesAt;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;

  alignas(8) std::uint8_t storage[32]{};
  const auto* base = reinterpret_cast<const std::byte*>(storage);

  WriteU32At(storage, 0, 0xA1B2C3D4u);
  WriteBytesAt(storage, 8, static_cast<std::uint16_t>(0xBEEF));
  const void* stored = storage + 16;
  WritePtrAt(storage, 16, stored);

  std::uint32_t u32 = 0;
  REQUIRE(ReadPod(base, 0, &u32, NotifyAlwaysReadable));
  CHECK(u32 == 0xA1B2C3D4u);

  std::uint32_t via_u32 = 0;
  REQUIRE(NotifyReadU32(base, 0, &via_u32, NotifyAlwaysReadable));
  CHECK(via_u32 == 0xA1B2C3D4u);

  std::uint16_t u16 = 0;
  REQUIRE(NotifyReadU16(base, 8, &u16, NotifyAlwaysReadable));
  CHECK(u16 == 0xBEEF);

  const std::byte* ptr = nullptr;
  REQUIRE(NotifyReadPtr(base, 16, &ptr, NotifyAlwaysReadable));
  CHECK(ptr == reinterpret_cast<const std::byte*>(stored));
}

TEST_CASE("ReadPod and NotifyRead* fail when readable returns false") {
  using esptool::esp::NotifyReadPtr;
  using esptool::esp::NotifyReadU16;
  using esptool::esp::NotifyReadU32;
  using esptool::esp::ReadPod;
  using esptool::esp::WriteU32At;

  alignas(8) std::uint8_t storage[16]{};
  WriteU32At(storage, 0, 0x11223344u);
  const auto* base = reinterpret_cast<const std::byte*>(storage);

  std::uint32_t u32 = 0xDEADBEEFu;
  CHECK_FALSE(ReadPod(base, 0, &u32, NeverReadable));
  CHECK(u32 == 0xDEADBEEFu);

  std::uint16_t u16 = 0xABCDu;
  CHECK_FALSE(NotifyReadU16(base, 0, &u16, NeverReadable));
  CHECK(u16 == 0xABCDu);

  CHECK_FALSE(NotifyReadU32(base, 0, &u32, NeverReadable));
  CHECK(u32 == 0xDEADBEEFu);

  const std::byte* ptr = reinterpret_cast<const std::byte*>(0x1);
  CHECK_FALSE(NotifyReadPtr(base, 0, &ptr, NeverReadable));
  CHECK(ptr == reinterpret_cast<const std::byte*>(0x1));
}

TEST_CASE("ReadPod and NotifyRead* fail on null base, out, or readable") {
  using esptool::esp::NotifyAlwaysReadable;
  using esptool::esp::NotifyReadPtr;
  using esptool::esp::NotifyReadU16;
  using esptool::esp::NotifyReadU32;
  using esptool::esp::ReadPod;

  alignas(8) std::uint8_t storage[16]{};
  const auto* base = reinterpret_cast<const std::byte*>(storage);
  std::uint16_t u16 = 0;
  std::uint32_t u32 = 0;
  const std::byte* ptr = nullptr;

  CHECK_FALSE(ReadPod<std::uint32_t>(nullptr, 0, &u32, NotifyAlwaysReadable));
  CHECK_FALSE(ReadPod<std::uint32_t>(base, 0, nullptr, NotifyAlwaysReadable));
  CHECK_FALSE(ReadPod(base, 0, &u32, nullptr));

  CHECK_FALSE(NotifyReadU16(nullptr, 0, &u16, NotifyAlwaysReadable));
  CHECK_FALSE(NotifyReadU16(base, 0, nullptr, NotifyAlwaysReadable));
  CHECK_FALSE(NotifyReadU16(base, 0, &u16, nullptr));

  CHECK_FALSE(NotifyReadU32(nullptr, 0, &u32, NotifyAlwaysReadable));
  CHECK_FALSE(NotifyReadU32(base, 0, nullptr, NotifyAlwaysReadable));
  CHECK_FALSE(NotifyReadU32(base, 0, &u32, nullptr));

  CHECK_FALSE(NotifyReadPtr(nullptr, 0, &ptr, NotifyAlwaysReadable));
  CHECK_FALSE(NotifyReadPtr(base, 0, &ptr, nullptr));
  CHECK_FALSE(NotifyReadPtr(base, 0, nullptr, NeverReadable));
}

TEST_CASE("NotifyReadPtr writes bit_cast of the stored uint64") {
  using esptool::esp::NotifyAlwaysReadable;
  using esptool::esp::NotifyReadPtr;
  using esptool::esp::WriteBytesAt;

  alignas(8) std::uint8_t storage[16]{};
  const auto* base = reinterpret_cast<const std::byte*>(storage);
  const std::uint64_t raw = 0x00007FF8A1B2C3D4ull;
  WriteBytesAt(storage, 0, raw);

  const std::byte* out = nullptr;
  REQUIRE(NotifyReadPtr(base, 0, &out, NotifyAlwaysReadable));
  CHECK(out == std::bit_cast<const std::byte*>(raw));
}

TEST_CASE("NotifyReadPtr returns false for a zero pointer") {
  using esptool::esp::NotifyAlwaysReadable;
  using esptool::esp::NotifyReadPtr;
  using esptool::esp::WriteBytesAt;

  alignas(8) std::uint8_t storage[16]{};
  const auto* base = reinterpret_cast<const std::byte*>(storage);
  WriteBytesAt(storage, 0, std::uint64_t{0});

  const std::byte* out = reinterpret_cast<const std::byte*>(0x1);
  CHECK_FALSE(NotifyReadPtr(base, 0, &out, NotifyAlwaysReadable));
  CHECK(out == nullptr);
}

TEST_CASE("QuerySlotAt and AtOffset use index times stride arithmetic") {
  using esptool::esp::AtOffset;
  using esptool::esp::QuerySlotAt;

  alignas(8) std::uint8_t storage[64]{};
  const auto* base = reinterpret_cast<const std::byte*>(storage);

  CHECK(AtOffset(base, 0) == base);
  CHECK(AtOffset(base, 24) == base + 24);
  CHECK(QuerySlotAt(base, 0, 16) == base);
  CHECK(QuerySlotAt(base, 3, 16) == base + 48);
  CHECK(QuerySlotAt(base, 2, 24) == base + 48);
}

TEST_CASE("WriteU32At WritePtrAt WriteBytesAt round-trip with memcpy") {
  using esptool::esp::Client;
  using esptool::esp::WriteBytesAt;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;

  alignas(8) std::uint8_t storage[32]{};

  WriteU32At(storage, 0, 0xAABBCCDDu);
  std::uint32_t u32 = 0;
  std::memcpy(&u32, storage, sizeof(u32));
  CHECK(u32 == 0xAABBCCDDu);

  const void* address = storage + 8;
  WritePtrAt(storage, 8, address);
  const void* via_ptr = nullptr;
  std::memcpy(&via_ptr, storage + 8, sizeof(via_ptr));
  CHECK(via_ptr == address);

  const Client client{const_cast<void*>(address)};
  WritePtrAt(storage, 16, client);
  void* via_opaque = nullptr;
  std::memcpy(&via_opaque, storage + 16, sizeof(via_opaque));
  CHECK(via_opaque == address);

  struct Packed {
    std::uint32_t a;
    std::uint16_t b;
  };
  const Packed value{0x01020304u, 0x5566};
  WriteBytesAt(storage, 0, value);
  Packed back{};
  std::memcpy(&back, storage, sizeof(back));
  CHECK(back.a == value.a);
  CHECK(back.b == value.b);
}
