#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>

#include "esp/EspCore.h"

namespace esptool::esp {

constexpr std::uint32_t kCollectionTypeInteger = 1;
constexpr std::uint32_t kCollectionTypeBinary = 3;
constexpr std::uint32_t kCollectionLifetimeMin = 1;
constexpr std::uint32_t kCollectionLifetimeMax = 3;
constexpr std::uint32_t kPathDescriptorKindDos = 1;
constexpr std::uint32_t kFileIdDescriptorKind = 2;
constexpr std::int32_t kContextKeyId = 1;
constexpr std::uint32_t kContextKeySource = 1;
constexpr std::uint32_t kContextKeyUpdateKind = 1;
constexpr std::uint32_t kContextKeyValueType = 0;
constexpr std::uint32_t kContextKeyEncodingEmpty = 0;

struct alignas(8) PathDescriptorRaw {
  std::uint32_t kind = kPathDescriptorKindDos;
  std::uint32_t reserved = 0;
  std::uint64_t byte_length = 0;
  const wchar_t* buffer = nullptr;
};
static_assert(sizeof(PathDescriptorRaw) == 24, "path descriptor 24");
static_assert(offsetof(PathDescriptorRaw, byte_length) == 8, "length at +8");
static_assert(offsetof(PathDescriptorRaw, buffer) == 16, "buffer at +16");

struct alignas(8) FileIdDescriptorRaw {
  std::uint32_t reserved0 = 0;
  std::uint32_t kind = kFileIdDescriptorKind;
  std::uint8_t file_id[16] = {};
};
static_assert(sizeof(FileIdDescriptorRaw) == 24, "file-id descriptor 24");
static_assert(offsetof(FileIdDescriptorRaw, kind) == 4, "kind at +4");
static_assert(offsetof(FileIdDescriptorRaw, file_id) == 8, "FILE_ID_128 at +8");

struct alignas(8) ContextKeyUpdateRaw {
  std::int32_t key_id = kContextKeyId;
  std::uint32_t source = kContextKeySource;
  std::uint32_t update_kind = kContextKeyUpdateKind;
  std::uint32_t flags = 0;
  std::uint32_t value_type = kContextKeyValueType;
  std::uint32_t encoding = kContextKeyEncodingEmpty;
  void* payload = nullptr;
};
static_assert(sizeof(ContextKeyUpdateRaw) == 32, "ESP_CONTEXT_KEY_UPDATE 32");
static_assert(offsetof(ContextKeyUpdateRaw, payload) == 24, "payload at +24");

[[nodiscard]] constexpr std::string_view CanonicalQueryKind(
    std::string_view kind) noexcept {
  if (kind == "process-token" || kind == "thread-token") {
    return "token";
  }
  if (kind == "stream") {
    return "filestream";
  }
  return kind;
}

[[nodiscard]] constexpr bool KindHasReferenceCreate(
    std::string_view kind) noexcept {
  return kind == "process" || kind == "thread" || kind == "process-token" ||
         kind == "thread-token" || kind == "token" || kind == "file" ||
         kind == "fileobject" || kind == "stream" || kind == "filestream" ||
         kind == "registry" || kind == "volume" || kind == "disk" ||
         kind == "desktop" || kind == "pipe" || kind == "mailslot" ||
         kind == "event";
}

[[nodiscard]] constexpr const char* QueryExportForKind(
    std::string_view kind) noexcept {
  kind = CanonicalQueryKind(kind);
  if (kind == "client") {
    return "EspQueryClientProperties";
  }
  if (kind == "desktop") {
    return "EspQueryDesktopProperties";
  }
  if (kind == "disk") {
    return "EspQueryDiskProperties";
  }
  if (kind == "fileobject") {
    return "EspQueryFileObjectProperties";
  }
  if (kind == "file") {
    return "EspQueryFileProperties";
  }
  if (kind == "filestream") {
    return "EspQueryFileStreamProperties";
  }
  if (kind == "ktm") {
    return "EspQueryKtmTransactionProperties";
  }
  if (kind == "mailslot") {
    return "EspQueryMailslotProperties";
  }
  if (kind == "pipe") {
    return "EspQueryPipeProperties";
  }
  if (kind == "process") {
    return "EspQueryProcessProperties";
  }
  if (kind == "registry-key-object") {
    return "EspQueryRegistryKeyObjectProperties";
  }
  if (kind == "registry") {
    return "EspQueryRegistryKeyProperties";
  }
  if (kind == "thread") {
    return "EspQueryThreadProperties";
  }
  if (kind == "token") {
    return "EspQueryTokenProperties";
  }
  if (kind == "volume") {
    return "EspQueryVolumeProperties";
  }
  return nullptr;
}

[[nodiscard]] constexpr const char* SupportExportForKind(
    std::string_view kind) noexcept {
  kind = CanonicalQueryKind(kind);
  if (kind == "client") {
    return "EspIsClientPropertySupported";
  }
  if (kind == "desktop") {
    return "EspIsDesktopPropertySupported";
  }
  if (kind == "disk") {
    return "EspIsDiskPropertySupported";
  }
  if (kind == "event") {
    return "EspIsEventPropertySupported";
  }
  if (kind == "fileobject") {
    return "EspIsFileObjectPropertySupported";
  }
  if (kind == "file") {
    return "EspIsFilePropertySupported";
  }
  if (kind == "filestream") {
    return "EspIsFileStreamPropertySupported";
  }
  if (kind == "ktm") {
    return "EspIsKtmTransactionPropertySupported";
  }
  if (kind == "mailslot") {
    return "EspIsMailslotPropertySupported";
  }
  if (kind == "pipe") {
    return "EspIsPipePropertySupported";
  }
  if (kind == "process") {
    return "EspIsProcessPropertySupported";
  }
  if (kind == "registry-key-object") {
    return "EspIsRegistryKeyObjectPropertySupported";
  }
  if (kind == "registry") {
    return "EspIsRegistryKeyPropertySupported";
  }
  if (kind == "thread") {
    return "EspIsThreadPropertySupported";
  }
  if (kind == "token") {
    return "EspIsTokenPropertySupported";
  }
  if (kind == "volume") {
    return "EspIsVolumePropertySupported";
  }
  return nullptr;
}

}  // namespace esptool::esp
