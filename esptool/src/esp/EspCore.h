#pragma once

#include <cstddef>
#include <cstdint>

namespace esptool::esp {

using EspResult = std::int32_t;

// Non-owning typed view of an espclient object. The session owns the
// lifetime. get()/abi() is the address written into rule blobs for the
// driver. That slot cannot be a shared_ptr or unique_ptr: those store a
// control block, and their deleters would double-close.
template <typename Tag>
class Opaque {
 public:
  Opaque() noexcept = default;
  explicit Opaque(void* raw) noexcept : raw_(raw) {}

  [[nodiscard]] void* get() const noexcept { return raw_; }
  [[nodiscard]] void* abi() const noexcept { return get(); }
  [[nodiscard]] explicit operator bool() const noexcept {
    return raw_ != nullptr;
  }
  [[nodiscard]] friend bool operator==(Opaque, Opaque) = default;

  void reset(void* raw = nullptr) noexcept { raw_ = raw; }

 private:
  void* raw_ = nullptr;
};

struct FilterTag {};
struct ClientTag {};
struct QueueTag {};
struct CollectionTag {};
struct RuleTag {};
struct NotificationTag {};
struct ObjectReferenceTag {};
struct EventObjectTag {};

using Filter = Opaque<FilterTag>;
using Client = Opaque<ClientTag>;
using Queue = Opaque<QueueTag>;
using Collection = Opaque<CollectionTag>;
using Rule = Opaque<RuleTag>;
using Notification = Opaque<NotificationTag>;
using ObjectReference = Opaque<ObjectReferenceTag>;
using EventObject = Opaque<EventObjectTag>;

namespace detail {

[[nodiscard]] inline void** AsSharedWrapperRaw(void* wrapper) noexcept {
  return static_cast<void**>(wrapper);
}

}  // namespace detail

template <typename Tag>
[[nodiscard]] inline void** AsSharedWrapper(Opaque<Tag> object) noexcept {
  return detail::AsSharedWrapperRaw(object.get());
}

struct Guid {
  std::uint32_t data1 = 0;
  std::uint16_t data2 = 0;
  std::uint16_t data3 = 0;
  std::uint8_t data4[8] = {};

  [[nodiscard]] friend constexpr bool operator==(const Guid&,
                                                 const Guid&) = default;
};

static_assert(sizeof(Guid) == 16, "Guid must be exactly 16 bytes");

[[nodiscard]] constexpr bool IsNull(const Guid& value) noexcept {
  return value == Guid{};
}

inline constexpr char kDefaultClientName[] = "esptool";
inline constexpr char kDefaultClientAltitude[] = "385000";
inline constexpr unsigned kDefaultClientAltitudeValue = 385000;
inline constexpr unsigned kAltitudeCollisionTries = 32;
inline constexpr unsigned kAltitudeCollisionStep = 10;
inline constexpr wchar_t kDefaultClientNameWide[] = L"esptool";
inline constexpr wchar_t kDefaultClientAltitudeWide[] = L"385000";
inline constexpr wchar_t kEspClientDll[] = L"espclient.dll";
constexpr std::size_t kContextKeyDwords = 8;

constexpr EspResult kOk = 0;
constexpr EspResult kFail = static_cast<EspResult>(0x80004005);
constexpr EspResult kAccessDenied = static_cast<EspResult>(0x80070005);
constexpr EspResult kOutOfMemory = static_cast<EspResult>(0x8007000E);
constexpr EspResult kInvalidArg = static_cast<EspResult>(0x80070057);
constexpr EspResult kInsufficientBuffer = static_cast<EspResult>(0x8007007A);
constexpr EspResult kModNotFound = static_cast<EspResult>(0x8007007E);
constexpr EspResult kAlreadyExists = static_cast<EspResult>(0x800700B7);
constexpr EspResult kNoMoreItems = static_cast<EspResult>(0x80070103);
constexpr EspResult kIoPending = static_cast<EspResult>(0x800703E5);
constexpr EspResult kNotFound = static_cast<EspResult>(0x80070490);
constexpr EspResult kTimeout = static_cast<EspResult>(0x800705B4);
constexpr EspResult kInvalidState = static_cast<EspResult>(0x8007139F);
constexpr EspResult kStatusAccessDenied = static_cast<EspResult>(0xC0000022);
constexpr EspResult kStatusInvalidParameter =
    static_cast<EspResult>(0xC000000D);
constexpr EspResult kStatusEntrypointNotFound =
    static_cast<EspResult>(0xC0000139);
constexpr EspResult kStatusAccessViolation = static_cast<EspResult>(0xC0000005);
constexpr EspResult kStatusStackBufferOverrun =
    static_cast<EspResult>(0xC0000409);
constexpr EspResult kStatusCancelled = static_cast<EspResult>(0xC0000120);

constexpr std::uint32_t kNtStatusErrorMask = 0xC0000000u;

static_assert(static_cast<std::uint32_t>(kInvalidArg) == 0x80070057u);
static_assert(static_cast<std::uint32_t>(kIoPending) == 0x800703E5u);
static_assert(static_cast<std::uint32_t>(kAlreadyExists) == 0x800700B7u);
static_assert(static_cast<std::uint32_t>(kStatusCancelled) == 0xC0000120u);

}  // namespace esptool::esp
