#include "esp/EspNotifyFormat.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <format>
#include <string_view>

#include "esp/EspEventIds.h"
#include "esp/EspNotifyDecode.h"
#include "util/StrHelpers.h"

namespace esptool::esp {
namespace {

[[nodiscard]] bool SafeProbeRead(const void* ptr, std::size_t size) noexcept {
  if (ptr == nullptr || size == 0) {
    return false;
  }
  __try {
    const volatile char* p = static_cast<const volatile char*>(ptr);
    volatile char dummy = p[0];
    dummy = p[size - 1];
    (void)dummy;
    return true;
  } __except (EXCEPTION_EXECUTE_HANDLER) {
    return false;
  }
}

[[nodiscard]] bool IsCommittedReadable(const std::byte* pointer,
                                       std::size_t size) noexcept {
  if (pointer == nullptr || size == 0) {
    return false;
  }
  auto* cursor = pointer;
  std::size_t remaining = size;
  while (remaining > 0) {
    MEMORY_BASIC_INFORMATION info{};
    if (VirtualQuery(static_cast<LPCVOID>(cursor), &info, sizeof(info)) == 0 ||
        info.State != MEM_COMMIT) {
      return false;
    }
    const DWORD protect = info.Protect & 0xFFu;
    if (protect == PAGE_NOACCESS || protect == PAGE_EXECUTE) {
      return false;
    }
    const auto* region_end =
        static_cast<const std::byte*>(info.BaseAddress) + info.RegionSize;
    if (cursor >= region_end) {
      return false;
    }
    const std::size_t chunk = static_cast<std::size_t>(region_end - cursor);
    const std::size_t take = chunk < remaining ? chunk : remaining;
    cursor += take;
    remaining -= take;
  }
  return SafeProbeRead(pointer, size);
}

[[nodiscard]] bool TryReadUnicodeString(const std::byte* us, std::string* out) {
  if (us == nullptr || out == nullptr) {
    return false;
  }
  std::uint16_t length = 0;
  const std::byte* buffer = nullptr;
  if (!NotifyReadU16(us, kUnicodeStringLengthOffset, &length,
                     IsCommittedReadable) ||
      !NotifyReadPtr(us, kUnicodeStringBufferOffset, &buffer,
                     IsCommittedReadable)) {
    return false;
  }
  if (length == 0 || (length & 1u) != 0 || length > 32766) {
    return false;
  }
  if (!IsCommittedReadable(buffer, length)) {
    return false;
  }
  const auto* text = reinterpret_cast<const wchar_t*>(buffer);
  *out = text::ToUtf8(std::wstring_view(text, length / 2));
  return true;
}

[[nodiscard]] bool TryReadNamePrimary(const std::byte* params,
                                      std::string* out) {
  const std::byte* object = nullptr;
  if (!NotifyReadPtr(params, kParamsObjectOffset, &object,
                     IsCommittedReadable)) {
    return false;
  }
  const std::byte* collection = nullptr;
  std::uint32_t count = 0;
  const std::byte* boxed = nullptr;
  std::uint32_t boxed_type = 0;
  const std::byte* us = nullptr;
  if (!NotifyReadPtr(object, kNameCollectionOffset, &collection,
                     IsCommittedReadable) ||
      !NotifyReadU32(collection, kNameCollectionCountOffset, &count,
                     IsCommittedReadable) ||
      count < 1 ||
      !NotifyReadPtr(collection, kNameBoxedOffset, &boxed,
                     IsCommittedReadable) ||
      !NotifyReadU32(boxed, kBoxedTypeOffset, &boxed_type,
                     IsCommittedReadable) ||
      !IsNameBoxedType(boxed_type) ||
      !NotifyReadPtr(boxed, kBoxedPayloadOffset, &us, IsCommittedReadable)) {
    return false;
  }
  return TryReadUnicodeString(us, out);
}

[[nodiscard]] bool TryReadNameAlternate(const std::byte* params,
                                        std::string* out) {
  const std::byte* wrapper = nullptr;
  if (!NotifyReadPtr(params, kParamsObjectOffset, &wrapper,
                     IsCommittedReadable)) {
    return false;
  }
  const std::byte* inner = nullptr;
  std::uint32_t status = 0;
  const std::byte* us = nullptr;
  if (!NotifyReadPtr(wrapper, kNameWrapperInnerOffsetAlternate, &inner,
                     IsCommittedReadable) ||
      !NotifyReadU32(inner, kWrapperStatusOffset, &status,
                     IsCommittedReadable) ||
      status != 0 ||
      !NotifyReadPtr(inner, kWrapperBlobOffset, &us, IsCommittedReadable)) {
    return false;
  }
  return TryReadUnicodeString(us, out);
}

[[nodiscard]] bool ReadNotificationHeader(const std::byte* bytes,
                                          std::uint32_t* kind,
                                          std::uint64_t* identifier,
                                          std::uint32_t* payload_length) {
  return ReadPod(bytes, kNotificationKindOffset, kind, IsCommittedReadable) &&
         ReadPod(bytes, kNotificationIdentifierOffset, identifier,
                 IsCommittedReadable) &&
         ReadPod(bytes, kNotificationPayloadLengthOffset, payload_length,
                 IsCommittedReadable);
}

[[nodiscard]] bool BindNotificationData(const std::byte* bytes,
                                        std::uint32_t* event_type,
                                        const std::byte** params,
                                        const std::byte** event_data) {
  bool uses_primary = false;
  std::size_t type_offset = 0;
  // ProcessCreate type is at notification+0xE0. Binding the generic
  // layout first false-matches type 1 at +120.
  if (TryBindLayout(bytes, kEventDataTypeOffsetProcess,
                    kNotificationProcessObjectOffset, event_type, params,
                    &uses_primary, true, &type_offset, IsCommittedReadable)) {
    if (event_data != nullptr) {
      *event_data = bytes;
    }
    return true;
  }
  for (std::size_t candidate : kNotificationDataCandidates) {
    const std::byte* candidate_data = nullptr;
    if (NotifyReadPtr(bytes, candidate, &candidate_data, IsCommittedReadable) &&
        TryBindEventData(candidate_data, event_type, params, &uses_primary,
                         &type_offset, IsCommittedReadable)) {
      if (event_data != nullptr) {
        *event_data = candidate_data;
      }
      static_cast<void>(uses_primary);
      static_cast<void>(type_offset);
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool TryReadNameFromPropertyValue(const std::byte* boxed,
                                                std::string* out) {
  std::uint8_t tag = 0;
  if (!ReadPod(boxed, kPropertyValueTagOffset, &tag, IsCommittedReadable) ||
      tag != kPropertyValueTagPath) {
    return false;
  }
  const std::byte* us = nullptr;
  if (!NotifyReadPtr(boxed, kBoxedPayloadOffset, &us, IsCommittedReadable)) {
    return false;
  }
  return TryReadUnicodeString(us, out);
}

[[nodiscard]] bool TryReadNameFromQuerySlot(const std::byte* slot,
                                            std::string* out) {
  if (slot == nullptr || out == nullptr) {
    return false;
  }
  std::uint32_t boxed_type = 0;
  const std::byte* us = nullptr;
  if (NotifyReadU32(slot, kQuerySlotTypeOffset, &boxed_type,
                    IsCommittedReadable) &&
      IsNameBoxedType(boxed_type) &&
      NotifyReadPtr(slot, kQuerySlotPayloadOffset, &us, IsCommittedReadable) &&
      TryReadUnicodeString(us, out)) {
    return true;
  }
  return TryReadNameFromPropertyValue(slot, out);
}

[[nodiscard]] bool TryReadNameFromNotificationQuery(
    const std::byte* notification, std::string* out) {
  const std::byte* slot = nullptr;
  if (TryReadNotificationQuerySlot(notification, 20, &slot,
                                   IsCommittedReadable) &&
      TryReadNameFromQuerySlot(slot, out)) {
    return true;
  }
  if (TryReadNotificationQuerySlot(notification, kProcessQueryPropertyName,
                                   &slot, IsCommittedReadable) &&
      TryReadNameFromQuerySlot(slot, out)) {
    return true;
  }
  if (!TryReadNotificationQueryNameSlot(notification, &slot,
                                        IsCommittedReadable)) {
    return false;
  }
  return TryReadNameFromQuerySlot(slot, out);
}

[[nodiscard]] bool TryReadNameFromQueryBag(const std::byte* params,
                                           std::string* out) {
  const std::byte* bag = nullptr;
  std::uint32_t count = 0;
  if (!NotifyReadPtr(params, kParamsPidBagOffset, &bag, IsCommittedReadable) ||
      !NotifyReadU32(bag, kObjectQueryCountOffset, &count,
                     IsCommittedReadable) ||
      count == 0) {
    return false;
  }
  for (std::uint32_t index = 0; index < count; ++index) {
    const std::byte* boxed = nullptr;
    std::uint32_t boxed_type = 0;
    const std::byte* us = nullptr;
    if (!NotifyReadPtr(bag,
                       kObjectQueryPtrOffset + static_cast<std::size_t>(index) *
                                                   kPropertyCollectionStride,
                       &boxed, IsCommittedReadable) ||
        !NotifyReadU32(boxed, kBoxedTypeOffset, &boxed_type,
                       IsCommittedReadable) ||
        !IsNameBoxedType(boxed_type) ||
        !NotifyReadPtr(boxed, kBoxedPayloadOffset, &us, IsCommittedReadable)) {
      if (TryReadNameFromPropertyValue(boxed, out)) {
        return true;
      }
      continue;
    }
    if (TryReadUnicodeString(us, out)) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] bool TryReadInlineNtPath(const std::byte* text,
                                       std::string* out) {
  if (text == nullptr || out == nullptr) {
    return false;
  }
  std::uint16_t first = 0;
  if (!NotifyReadU16(text, 0, &first, IsCommittedReadable) ||
      first != kNtPathFirstWchar) {
    return false;
  }
  constexpr std::size_t kMaxChars = 260;
  std::wstring wide;
  wide.reserve(64);
  for (std::size_t index = 0; index < kMaxChars; ++index) {
    std::uint16_t unit = 0;
    if (!NotifyReadU16(text, index * sizeof(std::uint16_t), &unit,
                       IsCommittedReadable)) {
      break;
    }
    if (unit == 0 || unit < 0x20 || unit > 0x7E) {
      break;
    }
    wide.push_back(static_cast<wchar_t>(unit));
  }
  if (wide.empty() || wide.front() != L'\\') {
    return false;
  }
  *out = text::ToUtf8(wide);
  return true;
}

[[nodiscard]] bool TryReadFoNotificationName(const std::byte* notification,
                                             std::uint32_t event_type,
                                             std::string* out) {
  const std::byte* source = nullptr;
  const FoNameLayout layout = ClassifyFoNotificationName(
      event_type, notification, &source, IsCommittedReadable);
  if (layout == FoNameLayout::UnicodeString) {
    return TryReadUnicodeString(source, out);
  }
  if (layout == FoNameLayout::InlineUtf16) {
    return TryReadInlineNtPath(source, out);
  }
  return false;
}

void ReadNotificationName(const std::byte* params, std::string* name) {
  if (params == nullptr) {
    return;
  }
  static_cast<void>(TryReadNameFromQueryBag(params, name));
  if (name->empty()) {
    static_cast<void>(TryReadNamePrimary(params, name));
  }
  if (name->empty()) {
    static_cast<void>(TryReadNameAlternate(params, name));
  }
}

[[nodiscard]] std::string_view EventFamilyName(
    std::uint32_t event_type) noexcept {
  if (event_type >= kEventProcessCreate &&
      event_type <= kEventProcessLoadImage) {
    return "Process";
  }
  if (event_type >= kEventThreadCreate && event_type <= kEventThreadTerminate) {
    return "Thread";
  }
  if (IsFoIoEvent(event_type)) {
    return "FileObject";
  }
  if (event_type == kEventPipeCreate) {
    return "Pipe";
  }
  if (event_type == kEventMailslotCreate) {
    return "Mailslot";
  }
  if (IsRegistryEventType(event_type)) {
    return "Registry";
  }
  if (event_type >= kEventFsMin && event_type <= kEventFsLockFile) {
    return "Filesystem";
  }
  if (event_type == 3010 || event_type == 3011) {
    return "Ktm";
  }
  if (event_type >= kEventVolumeMin && event_type <= kEventVolumeMax) {
    return "Volume";
  }
  if (event_type == kEventObCreateHandle ||
      event_type == kEventObDuplicateHandle) {
    return "Handle";
  }
  return "Unknown";
}

}  // namespace

std::string LookupPropertyName(std::string_view family, std::uint32_t id) {
  if (family == "Process") {
    switch (id) {
      case 1:
        return "CommandLine";
      case 2:
        return "SessionId";
      case 3:
        return "ParentProcessId";
      case 4:
        return "JobId";
      case 5:
        return "Affinity";
      case 6:
        return "ProcessId";
      case 7:
        return "ExitStatus";
      case 8:
        return "CreateTime";
      case 9:
        return "ExitTime";
      case 10:
        return "KernelTime";
      case 11:
        return "UserTime";
      case 12:
        return "ExitStatus";
      case 13:
        return "UniqueProcessKey";
      case 14:
        return "ProcessStartTime";
      case 16:
        return "Wow64Process";
      case 17:
        return "ProtectionLevel";
      case 18:
        return "MitigationFlags";
      case 19:
        return "TokenElevation";
      case 20:
        return "ImagePath";
      case 21:
        return "Subsystem";
      case 22:
        return "Machine";
      default:
        return std::format("ProcessProp_{}", id);
    }
  }
  if (family == "Thread") {
    switch (id) {
      case 1:
        return "ThreadId";
      case 2:
        return "ProcessId";
      case 3:
        return "CreateTime";
      case 4:
        return "ExitTime";
      case 5:
        return "StartAddress";
      case 6:
        return "Subsystem";
      case 7:
        return "Win32StartAddress";
      default:
        return std::format("ThreadProp_{}", id);
    }
  }
  if (family == "FileObject") {
    switch (id) {
      case 1:
        return "FileName";
      case 2:
        return "Disposition";
      case 3:
        return "AccessMask";
      case 4:
        return "ShareAccess";
      case 5:
        return "CreateOptions";
      case 6:
        return "FileAttributes";
      case 7:
        return "StreamName";
      case 8:
        return "EndOfFile";
      case 9:
        return "VolumeName";
      case 10:
        return "FileIndex";
      case 18:
        return "FileId";
      case 28:
        return "FileObjectType";
      default:
        return std::format("FileObjectProp_{}", id);
    }
  }
  if (family == "Pipe") {
    switch (id) {
      case 1:
        return "PipeName";
      case 2:
        return "PipeConfiguration";
      case 3:
        return "MaxInstances";
      case 4:
        return "CurrentInstances";
      default:
        return std::format("PipeProp_{}", id);
    }
  }
  if (family == "Mailslot") {
    switch (id) {
      case 1:
        return "MailslotName";
      case 2:
        return "MaxMessageSize";
      case 3:
        return "ReadTimeout";
      default:
        return std::format("MailslotProp_{}", id);
    }
  }
  if (family == "Registry") {
    switch (id) {
      case 1:
        return "KeyPath";
      case 2:
        return "ValueName";
      case 3:
        return "ValueType";
      case 4:
        return "ValueData";
      case 5:
        return "Class";
      case 6:
        return "TitleIndex";
      default:
        return std::format("RegistryProp_{}", id);
    }
  }
  if (family == "Filesystem") {
    switch (id) {
      case 1:
        return "FileName";
      case 2:
        return "FileInformationClass";
      case 3:
        return "FileAccess";
      case 4:
        return "AllocationSize";
      case 5:
        return "EndOfFile";
      case 6:
        return "FileAttributes";
      case 7:
        return "SecurityInformation";
      case 8:
        return "EaName";
      case 9:
        return "FsctlCode";
      default:
        return std::format("FsProp_{}", id);
    }
  }
  if (family == "Volume") {
    switch (id) {
      case 1:
        return "VolumeGuid";
      case 2:
        return "DeviceName";
      case 3:
        return "FileSystemType";
      case 4:
        return "FsctlCode";
      default:
        return std::format("VolumeProp_{}", id);
    }
  }
  if (family == "Ktm") {
    switch (id) {
      case 1:
        return "TransactionId";
      case 2:
        return "TransactionUow";
      case 3:
        return "IsolationLevel";
      case 4:
        return "Timeout";
      default:
        return std::format("KtmProp_{}", id);
    }
  }
  if (family == "Handle") {
    switch (id) {
      case 1:
        return "Handle";
      case 2:
        return "DesiredAccess";
      case 3:
        return "GrantedAccess";
      case 4:
        return "TargetProcessId";
      case 5:
        return "SourceProcessId";
      default:
        return std::format("HandleProp_{}", id);
    }
  }
  if (family == "Token") {
    switch (id) {
      case 1:
        return "TokenUserSid";
      case 2:
        return "TokenGroups";
      case 3:
        return "TokenPrivileges";
      case 4:
        return "TokenOwner";
      case 5:
        return "TokenPrimaryGroup";
      case 6:
        return "TokenDefaultDacl";
      case 7:
        return "TokenType";
      case 8:
        return "TokenImpersonationLevel";
      case 9:
        return "TokenElevationType";
      case 10:
        return "TokenIntegrityLevel";
      case 11:
        return "TokenAppContainer";
      default:
        return std::format("TokenProp_{}", id);
    }
  }
  if (family == "Desktop") {
    switch (id) {
      case 1:
        return "DesktopName";
      case 2:
        return "SessionId";
      default:
        return std::format("DesktopProp_{}", id);
    }
  }
  return std::format("Prop_{}", id);
}

namespace {

void ReadNotificationProperties(const std::byte* bytes,
                                std::uint32_t event_type,
                                const std::byte* params,
                                std::vector<DecodedProperty>& out) {
  if (bytes == nullptr) {
    return;
  }
  const std::string_view event_family = EventFamilyName(event_type);
  std::uint32_t query_count = 0;
  const std::byte* query_array = nullptr;
  if (NotifyReadU32(bytes, kNotificationQueryCountOffset, &query_count,
                    IsCommittedReadable) &&
      query_count > 0 && query_count <= 256 &&
      NotifyReadPtr(bytes, kNotificationQueryPtrOffset, &query_array,
                    IsCommittedReadable) &&
      query_array != nullptr) {
    for (std::uint32_t i = 0; i < query_count; ++i) {
      const std::byte* cursor = query_array + i * kQuerySlotStride;
      if (!IsCommittedReadable(cursor, kQuerySlotStride)) {
        continue;
      }
      std::uint32_t prop_id = 0;
      std::uint32_t prop_type = 0;
      std::uint64_t prop_value = 0;
      if (!NotifyReadU32(cursor, kQuerySlotPropertyOffset, &prop_id,
                         IsCommittedReadable) ||
          !NotifyReadU32(cursor, kQuerySlotTypeOffset, &prop_type,
                         IsCommittedReadable) ||
          !ReadPod(cursor, kQuerySlotPayloadOffset, &prop_value,
                   IsCommittedReadable)) {
        continue;
      }
      if (std::ranges::any_of(out, [&](const DecodedProperty& p) {
            return p.family == event_family && p.id == prop_id;
          })) {
        continue;
      }
      DecodedProperty prop;
      prop.family = std::string(event_family);
      prop.id = prop_id;
      prop.type = prop_type;
      prop.raw_value = prop_value;
      prop.name = LookupPropertyName(event_family, prop_id);
      if (prop_type == kBoxedTypeUnicodeString ||
          prop_type == kBoxedTypePathString) {
        const auto* desc = reinterpret_cast<const std::byte*>(
            static_cast<std::uintptr_t>(prop_value));
        std::string str_val;
        if (TryReadUnicodeString(desc, &str_val) && !str_val.empty()) {
          prop.formatted_value = std::move(str_val);
          prop.is_string = true;
        } else {
          prop.formatted_value = std::format("0x{:X}", prop_value);
        }
      } else if (prop_type == kBoxedTypeU32 || prop_type == kBoxedTypeInt32) {
        prop.formatted_value =
            std::format("{} (0x{:X})", static_cast<std::uint32_t>(prop_value),
                        static_cast<std::uint32_t>(prop_value));
      } else if (prop_type == kBoxedTypeInt64) {
        prop.formatted_value =
            std::format("{} (0x{:X})", prop_value, prop_value);
      } else {
        prop.formatted_value =
            std::format("{} (0x{:X})", prop_value, prop_value);
      }
      out.push_back(std::move(prop));
    }
  }

  if (params != nullptr) {
    const auto read_bag = [&](std::size_t bag_offset, std::string_view family) {
      const std::byte* bag = nullptr;
      std::uint32_t count = 0;
      const std::byte* items = nullptr;
      if (!NotifyReadPtr(params, bag_offset, &bag, IsCommittedReadable) ||
          !NotifyReadU32(bag, kObjectQueryCountOffset, &count,
                         IsCommittedReadable) ||
          count == 0 || count > 64 ||
          !NotifyReadPtr(bag, kObjectQueryPtrOffset, &items,
                         IsCommittedReadable) ||
          items == nullptr) {
        return;
      }
      for (std::uint32_t i = 0; i < count; ++i) {
        const auto* cursor = items + i * kPropertyCollectionStride;
        if (!IsCommittedReadable(cursor, kPropertyCollectionStride)) {
          continue;
        }
        std::uint32_t prop_id = 0;
        std::uint32_t prop_type = 0;
        std::uint64_t prop_val = 0;
        if (NotifyReadU32(cursor, kBoxedTypeOffset, &prop_type,
                          IsCommittedReadable) &&
            ReadPod(cursor, kBoxedPayloadOffset, &prop_val,
                    IsCommittedReadable) &&
            NotifyReadU32(cursor, 0, &prop_id, IsCommittedReadable)) {
          if (std::ranges::any_of(out, [&](const DecodedProperty& p) {
                return p.family == family && p.id == prop_id;
              })) {
            continue;
          }
          DecodedProperty prop;
          prop.family = std::string(family);
          prop.id = prop_id;
          prop.type = prop_type;
          prop.raw_value = prop_val;
          prop.name = LookupPropertyName(family, prop_id);
          if (IsNameBoxedType(prop_type)) {
            const auto* desc = reinterpret_cast<const std::byte*>(
                static_cast<std::uintptr_t>(prop_val));
            std::string str_val;
            if (TryReadUnicodeString(desc, &str_val) && !str_val.empty()) {
              prop.formatted_value = std::move(str_val);
              prop.is_string = true;
            } else {
              prop.formatted_value = std::format("0x{:X}", prop_val);
            }
          } else if (prop_type == kBoxedTypeU32 ||
                     prop_type == kBoxedTypeInt32) {
            prop.formatted_value =
                std::format("{} (0x{:X})", static_cast<std::uint32_t>(prop_val),
                            static_cast<std::uint32_t>(prop_val));
          } else {
            prop.formatted_value =
                std::format("{} (0x{:X})", prop_val, prop_val);
          }
          out.push_back(std::move(prop));
        }
      }
    };
    read_bag(kParamsPidBagOffset, "Process");
    read_bag(kParamsTidBagOffset, "Thread");
    read_bag(kParamsObjectOffset, event_family);
  }
}

}  // namespace

bool DecodeNotificationKeys(const std::byte* bytes, NotificationKeys& out) {
  out = NotificationKeys{};
  if (bytes == nullptr) {
    return false;
  }
  std::uint32_t kind = 0;
  std::uint64_t identifier = 0;
  std::uint32_t payload_length = 0;
  if (!ReadNotificationHeader(bytes, &kind, &identifier, &payload_length)) {
    return false;
  }
  static_cast<void>(kind);
  static_cast<void>(identifier);
  static_cast<void>(payload_length);

  std::uint32_t event_type = 0;
  const std::byte* params = nullptr;
  const std::byte* event_data = nullptr;
  static_cast<void>(
      BindNotificationData(bytes, &event_type, &params, &event_data));

  std::uint32_t pid = 0;
  std::uint32_t tid = 0;
  std::string name;
  static_cast<void>(
      TryReadNotificationQueryPid(bytes, &pid, IsCommittedReadable));
  static_cast<void>(TryReadNameFromNotificationQuery(bytes, &name));
  if (name.empty() && IsFoIoEvent(event_type)) {
    static_cast<void>(TryReadFoNotificationName(bytes, event_type, &name));
  }
  if (params != nullptr) {
    if (pid == 0) {
      static_cast<void>(
          TryReadPidTidFromParams(params, &pid, &tid, IsCommittedReadable));
    }
    if (name.empty()) {
      ReadNotificationName(params, &name);
    }
  }
  if (pid == 0 && event_data != nullptr && event_type >= kEventProcessCreate &&
      event_type <= kEventProcessLoadImage) {
    constexpr std::array<std::size_t, 4> process_object_offs{
        kEventDataProcessObjectOffset,
        kNotificationProcessObjectOffset,
        kProcessCreateChildObjectOffset,
        kProcessCreateActorObjectOffset,
    };
    for (const std::size_t off : process_object_offs) {
      const std::byte* process_object = nullptr;
      if (!NotifyReadPtr(event_data, off, &process_object,
                         IsCommittedReadable)) {
        continue;
      }
      static_cast<void>(TryReadPidTidFromParams(process_object, &pid, &tid,
                                                IsCommittedReadable));
      if (name.empty()) {
        ReadNotificationName(process_object, &name);
      }
      if (pid != 0 || !name.empty()) {
        break;
      }
    }
  }

  ReadNotificationProperties(bytes, event_type, params, out.properties);

  for (const auto& prop : out.properties) {
    if (pid == 0 && prop.family == "Process" && prop.id == 6) {
      pid = static_cast<std::uint32_t>(prop.raw_value);
    }
    if (tid == 0 && prop.family == "Thread" && prop.id == 1) {
      tid = static_cast<std::uint32_t>(prop.raw_value);
    }
    if (name.empty()) {
      if (event_type >= kEventProcessCreate &&
          event_type <= kEventProcessLoadImage) {
        if (prop.family == "Process" && prop.id == 20 && prop.is_string) {
          name = prop.formatted_value;
        }
      } else {
        if (prop.id == 1 && prop.is_string) {
          name = prop.formatted_value;
        }
      }
    }
  }

  out.event_type = event_type;
  out.pid = pid;
  out.tid = tid;
  out.name = std::move(name);
  return event_type != 0 || out.pid != 0 || !out.name.empty() ||
         !out.properties.empty();
}

std::string FormatEmptyNotificationLine(unsigned index) {
  return std::format(
      "notification {} id=0 kind=0 payload=0 event=0 pid=0 tid=0 name=-",
      index);
}

std::string FormatQueueNotification(const std::byte* bytes, unsigned index) {
  std::uint32_t kind = 0;
  std::uint64_t identifier = 0;
  std::uint32_t payload_length = 0;
  if (!ReadNotificationHeader(bytes, &kind, &identifier, &payload_length)) {
    return FormatEmptyNotificationLine(index);
  }
  NotificationKeys keys;
  static_cast<void>(DecodeNotificationKeys(bytes, keys));
  std::string line = std::format(
      "notification {} id={} kind={} payload={} event={} pid={} tid={} name={}",
      index, identifier, kind, payload_length, keys.event_type, keys.pid,
      keys.tid, keys.name.empty() ? "-" : keys.name);

  for (const auto& prop : keys.properties) {
    line += std::format("\n  prop[{}:{}] ({}, type {}): {}", prop.family,
                        prop.id, prop.name.empty() ? "Property" : prop.name,
                        prop.type, prop.formatted_value);
  }
  return line;
}

}  // namespace esptool::esp
