#include "esp/EspSession.h"

#include <Windows.h>

#include <array>
#include <bit>
#include <cstdio>
#include <cstring>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <vector>

#include "esp/EspFilterAbi.h"
#include "esp/EspMemoryView.h"
#include "esp/EspNotifyFormat.h"
#include "esp/EspNtPath.h"
#include "esp/EspStatus.h"
#include "util/Log.h"
#include "util/StrHelpers.h"

namespace esptool::esp {
namespace {

void WriteCollectionCreateDesc(std::uint8_t* desc, std::uint32_t type) {
  WriteU32At(desc, 16, type);
  WriteU32At(desc, 20, kCollectionStringSubtype);
}

[[nodiscard]] PathDescriptorRaw MakePathDescriptor(const std::wstring& path) {
  PathDescriptorRaw descriptor;
  descriptor.kind = kPathDescriptorKindDos;
  descriptor.byte_length = path.size() * sizeof(wchar_t);
  descriptor.buffer = path.c_str();
  return descriptor;
}

[[nodiscard]] bool ParseHexBytes(std::string_view text,
                                 std::vector<std::uint8_t>& out) {
  out.clear();
  std::string hex;
  hex.reserve(text.size());
  for (const char ch : text) {
    if (ch == ' ' || ch == '\t' || ch == '\r' || ch == '\n' || ch == '-') {
      continue;
    }
    hex.push_back(ch);
  }
  if (hex.empty() || (hex.size() % 2) != 0) {
    return false;
  }
  out.reserve(hex.size() / 2);
  for (std::size_t index = 0; index < hex.size(); index += 2) {
    std::string token = "0x";
    token.push_back(hex[index]);
    token.push_back(hex[index + 1]);
    std::uint64_t byte = 0;
    if (!text::ParseUnsigned(token, byte) || byte > 255) {
      return false;
    }
    out.push_back(static_cast<std::uint8_t>(byte));
  }
  return true;
}

}  // namespace

void EspSession::FreeEspBuffer(void* buffer) {
  if (buffer == nullptr) {
    return;
  }
  if (const auto fn = RequireTyped<FreeMemoryFn>("EspFreeMemory")) {
    fn(buffer);
  }
}

void EspSession::CloseReference(ObjectReference& ref) {
  const void* raw = ref.get();
  CloseOne(ref, "EspCloseEventObjectReference");
  for (ObjectReference& stored : object_refs_) {
    if (stored.get() == raw) {
      stored.reset();
    }
  }
}

bool EspSession::CreatePidReference(std::string_view export_name, int pid,
                                    ObjectReference& out) {
  const auto fn = RequireTyped<CreatePidReferenceFn>(export_name);
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  if (!Adopt(export_name, out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), pid, slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreatePathReference(std::string_view export_name,
                                     std::wstring_view path,
                                     ObjectReference& out) {
  const auto fn = RequireTyped<CreatePathDescriptorReferenceFn>(export_name);
  if (fn == nullptr || !client_handle_ || path.empty()) {
    return false;
  }
  path_storage_.emplace_back(path);
  const PathDescriptorRaw descriptor = MakePathDescriptor(path_storage_.back());
  if (!Adopt(export_name, out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_),
                  const_cast<PathDescriptorRaw*>(&descriptor), slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreateDesktopReference(std::wstring_view name,
                                        ObjectReference& out) {
  const auto fn =
      RequireTyped<CreateDesktopReferenceFn>("EspCreateDesktopReference");
  if (fn == nullptr || !client_handle_ || name.empty()) {
    return false;
  }
  path_storage_.emplace_back(name);
  if (!Adopt("EspCreateDesktopReference", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_),
                  path_storage_.back().c_str(), slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreateVolumeReference(const Guid& volume,
                                       ObjectReference& out) {
  const auto fn =
      RequireTyped<CreateVolumeReferenceFn>("EspCreateVolumeReference");
  if (fn == nullptr || !client_handle_ || IsNull(volume)) {
    return false;
  }
  Guid copy = volume;
  if (!Adopt("EspCreateVolumeReference", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), &copy, slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreateFileIdReference(const Guid& volume,
                                       const FileIdDescriptorRaw& file_id,
                                       ObjectReference& out) {
  const auto fn =
      RequireTyped<CreateFileIdReferenceFn>("EspCreateFileReferenceById");
  if (fn == nullptr || !client_handle_ || IsNull(volume)) {
    return false;
  }
  file_id_storage_.push_back(file_id);
  Guid volume_copy = volume;
  if (!Adopt("EspCreateFileReferenceById", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), &volume_copy,
                  &file_id_storage_.back(), slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreateStreamByIdReference(
    const Guid& volume, const FileIdDescriptorRaw& file_id,
    const wchar_t* stream_name, ObjectReference& out) {
  const auto fn =
      RequireTyped<CreateStreamByIdFn>("EspCreateFileStreamReferenceById");
  if (fn == nullptr || !client_handle_ || IsNull(volume)) {
    return false;
  }
  file_id_storage_.push_back(file_id);
  Guid volume_copy = volume;
  if (!Adopt("EspCreateFileStreamReferenceById", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), &volume_copy,
                  &file_id_storage_.back(), stream_name, slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::CreateEventObjectById(std::uint64_t event_object_id,
                                       ObjectReference& out) {
  const auto fn =
      RequireTyped<CreateEventByIdFn>("EspCreateEventObjectReferenceById");
  if (fn == nullptr || !client_handle_ || event_object_id == 0) {
    return false;
  }
  if (!Adopt("EspCreateEventObjectReferenceById", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), event_object_id, slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::UnwrapReference(const ObjectReference& ref, EventObject& view) {
  const auto fn =
      RequireTyped<GetEventObjectFn>("EspGetEventObjectFromReference");
  if (fn == nullptr || !ref) {
    return false;
  }
  return Adopt("EspGetEventObjectFromReference", view,
               [&](void** slot) { return fn(AsSharedWrapper(ref), slot); });
}

bool EspSession::DuplicateReference(const ObjectReference& ref,
                                    ObjectReference& out) {
  const auto fn =
      RequireTyped<DuplicateReferenceFn>("EspDuplicateEventObjectReference");
  if (fn == nullptr || !ref) {
    return false;
  }
  if (!Adopt("EspDuplicateEventObjectReference", out, [&](void** slot) {
        return fn(AsSharedWrapper(ref), slot);
      })) {
    return false;
  }
  object_refs_.push_back(out);
  return true;
}

bool EspSession::GetEventObjectId(const EventObject& view, std::uint64_t& id) {
  const auto fn = RequireTyped<GetEventObjectIdFn>("EspGetEventObjectId");
  if (fn == nullptr || !view) {
    return false;
  }
  id = 0;
  const EspResult result = fn(view.get(), &id);
  Record("EspGetEventObjectId", result);
  if (Succeeded(result)) {
    std::printf("event-object-id %llu\n",
                static_cast<unsigned long long>(id));
  }
  return Succeeded(result);
}

bool EspSession::GetEventObjectType(const EventObject& view, int& type) {
  const auto fn = RequireTyped<GetEventObjectTypeFn>("EspGetEventObjectType");
  if (fn == nullptr || !view) {
    return false;
  }
  type = 0;
  const EspResult result = fn(view.get(), &type);
  Record("EspGetEventObjectType", result);
  if (Succeeded(result)) {
    std::printf("event-object-type %d\n", type);
  }
  return Succeeded(result);
}

bool EspSession::SetEventObjectContextKey(const ObjectReference& ref) {
  const auto fn =
      RequireTyped<SetContextKeyFn>("EspSetEventObjectContextKey");
  if (fn == nullptr || !ref) {
    return false;
  }
  ContextKeyUpdateRaw key;
  const EspResult result = fn(AsSharedWrapper(ref), &key);
  Record("EspSetEventObjectContextKey", result);
  return Succeeded(result);
}

bool EspSession::EnumerateEventObjectContextKeys(const ObjectReference& ref) {
  const auto fn = RequireTyped<EnumerateContextKeysFn>(
      "EspEnumerateAllEventObjectContextKeys");
  if (fn == nullptr || !ref) {
    return false;
  }
  int count = 0;
  void* keys = nullptr;
  const EspResult result = fn(AsSharedWrapper(ref), &count, &keys);
  Record("EspEnumerateAllEventObjectContextKeys", result);
  std::printf("event-object-context-keys %d\n", count);
  FreeEspBuffer(keys);
  return Succeeded(result);
}

bool EspSession::IsPropertySupported(std::string_view kind,
                                     unsigned property_id,
                                     std::uint32_t& supported) {
  const char* export_name = SupportExportForKind(kind);
  if (export_name == nullptr || !client_handle_) {
    return false;
  }
  const auto fn = RequireTyped<IsPropertySupportedFn>(export_name);
  if (fn == nullptr) {
    return false;
  }
  supported = 0;
  const EspResult result =
      fn(AsSharedWrapper(client_handle_), property_id, &supported);
  Record(export_name, result);
  std::printf("property-supported %s %u %u\n", std::string(kind).c_str(),
              property_id, supported);
  return Succeeded(result);
}

bool EspSession::QueryKind(std::string_view kind, EventObject view,
                           const unsigned* ids, unsigned count) {
  if (kind == "event") {
    Warn("EspQueryEventProperties is not exported");
    return false;
  }
  const char* export_name = QueryExportForKind(kind);
  if (export_name == nullptr) {
    Warn(std::format("unknown query kind: {}", kind));
    return false;
  }
  const auto fn = RequireTyped<QueryPropertiesFn>(export_name);
  if (fn == nullptr) {
    return false;
  }
  void** object = kind == "client" ? AsSharedWrapper(client_handle_)
                                   : AsSharedWrapper(view);
  if (object == nullptr || (kind != "client" && !view)) {
    return false;
  }
  if (count == 0 || ids == nullptr) {
    Warn("QueryKind requires count >= 1");
    return false;
  }
  void* buffer = nullptr;
  const EspResult result = fn(object, count, ids, &buffer);
  Record(export_name, result);
  std::printf("query %s 0x%08x buffer=%p\n", export_name,
              static_cast<unsigned>(result), buffer);
  FreeEspBuffer(buffer);
  return Succeeded(result);
}

bool EspSession::OpenNamedCollection(const Guid& id, Collection& out) {
  const auto fn = RequireTyped<OpenCollectionFn>("EspOpenCollection");
  if (fn == nullptr || !client_handle_ || IsNull(id)) {
    return false;
  }
  Guid copy = id;
  if (!Adopt("EspOpenCollection", out, [&](void** slot) {
        return fn(AsSharedWrapper(client_handle_), &copy, slot);
      })) {
    return false;
  }
  collections_.push_back(out);
  return true;
}

bool EspSession::EnumerateCollectionIds(int lifetime, int& count,
                                        std::vector<Guid>* ids) {
  const auto fn =
      RequireTyped<EnumerateCollectionIdsFn>("EspEnumerateCollectionIds");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  if (lifetime < static_cast<int>(kCollectionLifetimeMin) ||
      lifetime > static_cast<int>(kCollectionLifetimeMax)) {
    Warn("EspEnumerateCollectionIds lifetime must be 1, 2, or 3");
    return false;
  }
  count = 0;
  void* buffer = nullptr;
  const EspResult result =
      fn(AsSharedWrapper(client_handle_), lifetime, &count, &buffer);
  Record("EspEnumerateCollectionIds", result);
  std::printf("collection-ids lifetime=%d count=%d\n", lifetime, count);
  if (ids != nullptr && buffer != nullptr && count > 0) {
    const auto* guid_ptr = static_cast<const Guid*>(buffer);
    ids->assign(guid_ptr, guid_ptr + count);
    for (const Guid& id : *ids) {
      const auto bytes = std::bit_cast<std::array<std::uint8_t, 16>>(id);
      std::printf("collection-id %s\n", text::FormatGuid(bytes).c_str());
    }
  }
  FreeEspBuffer(buffer);
  return Succeeded(result);
}

Collection EspSession::FindNamedCollection(std::string_view name) const {
  for (const auto& entry : named_collections_) {
    if (entry.first == name) {
      return entry.second;
    }
  }
  return {};
}

bool EspSession::InstallDocumentCollections(
    const model::RuleDocument& document) {
  const auto create_fn =
      RequireTyped<CreateCollectionFn>("EspCreateCollection");
  const auto update_fn =
      RequireTyped<UpdateCollectionFn>("EspUpdateCollection");
  if (create_fn == nullptr || update_fn == nullptr || !client_handle_) {
    return document.collections.empty();
  }
  bool all_ok = true;
  for (const model::CollectionSpec& spec : document.collections) {
    Collection collection;
    if (spec.open) {
      if (!spec.hasGuid || IsNull(spec.guid)) {
        Warn("open collection requires a guid");
        all_ok = false;
        continue;
      }
      if (!OpenNamedCollection(spec.guid, collection)) {
        all_ok = false;
        continue;
      }
    } else {
      alignas(8) std::array<std::uint8_t, 32> desc{};
      WriteCollectionCreateDesc(desc.data(), spec.type);
      if (!Adopt("EspCreateCollection", collection, [&](void** slot) {
            return create_fn(AsSharedWrapper(client_handle_), desc.data(),
                             slot);
          })) {
        all_ok = false;
        continue;
      }
      collections_.push_back(collection);
      for (const std::string& entry_text : spec.entries) {
        if (spec.type == kCollectionTypeInteger) {
          std::uint64_t parsed = 0;
          if (!text::ParseUnsigned(entry_text, parsed)) {
            Warn("integer collection entry is not a number");
            all_ok = false;
            continue;
          }
          CollectionIntegerUpdateEntry entry{};
          entry.value = static_cast<std::int64_t>(parsed);
          integer_entries_.push_back(entry);
          const EspResult update_result =
              update_fn(AsSharedWrapper(collection), 0, 1,
                        &integer_entries_.back());
          Record("EspUpdateCollection", update_result);
          if (Failed(update_result)) {
            all_ok = false;
          }
        } else if (spec.type == kCollectionTypeBinary) {
          std::vector<std::uint8_t> bytes;
          if (!ParseHexBytes(entry_text, bytes) || bytes.empty()) {
            Warn("binary collection entry is not hex");
            all_ok = false;
            continue;
          }
          binary_storage_.push_back(std::move(bytes));
          CollectionBinaryUpdateEntry entry{};
          entry.byte_count =
              static_cast<std::uint32_t>(binary_storage_.back().size());
          entry.data = binary_storage_.back().data();
          binary_entries_.push_back(entry);
          const EspResult update_result =
              update_fn(AsSharedWrapper(collection), 0, 1,
                        &binary_entries_.back());
          Record("EspUpdateCollection", update_result);
          if (Failed(update_result)) {
            all_ok = false;
          }
        } else {
          const std::wstring expanded = ExpandFilterValue(entry_text);
          if (expanded.empty()) {
            Warn("string collection entry is empty");
            all_ok = false;
            continue;
          }
          filter_strings_.push_back(expanded);
          CollectionUpdateEntry entry{};
          entry.operation = kCollectionUpdateAdd;
          const std::uint64_t bytes =
              filter_strings_.back().size() * sizeof(wchar_t);
          if (bytes == 0 || bytes > kMaxUtf16Bytes) {
            all_ok = false;
            continue;
          }
          entry.utf16_bytes = static_cast<std::uint16_t>(bytes);
          entry.text = filter_strings_.back().c_str();
          collection_entries_.push_back(entry);
          const EspResult update_result =
              update_fn(AsSharedWrapper(collection), 0, 1,
                        &collection_entries_.back());
          Record("EspUpdateCollection", update_result);
          if (Failed(update_result)) {
            all_ok = false;
          }
        }
      }
    }
    if (collection && !spec.name.empty()) {
      named_collections_.emplace_back(spec.name, collection);
    }
  }
  return all_ok;
}

bool EspSession::ExerciseCollectionsExtended(int lifetime, bool enum_ids,
                                             bool do_open, const Guid* open_id,
                                             std::uint32_t create_type) {
  Collection created{};
  if (create_type == kCollectionTypeInteger) {
    alignas(8) std::array<std::uint8_t, 32> desc{};
    WriteCollectionCreateDesc(desc.data(), kCollectionTypeInteger);
    const auto create_fn =
        RequireTyped<CreateCollectionFn>("EspCreateCollection");
    const auto update_fn =
        RequireTyped<UpdateCollectionFn>("EspUpdateCollection");
    if (create_fn == nullptr || update_fn == nullptr || !client_handle_ ||
        !Adopt("EspCreateCollection", created, [&](void** slot) {
          return create_fn(AsSharedWrapper(client_handle_), desc.data(), slot);
        })) {
      return false;
    }
    collections_.push_back(created);
    CollectionIntegerUpdateEntry entry{};
    entry.value = 42;
    integer_entries_.push_back(entry);
    const EspResult update_result =
        update_fn(AsSharedWrapper(created), 0, 1, &integer_entries_.back());
    Record("EspUpdateCollection", update_result);
    if (Failed(update_result)) {
      return false;
    }
  } else if (create_type == kCollectionTypeBinary) {
    alignas(8) std::array<std::uint8_t, 32> desc{};
    WriteCollectionCreateDesc(desc.data(), kCollectionTypeBinary);
    const auto create_fn =
        RequireTyped<CreateCollectionFn>("EspCreateCollection");
    const auto update_fn =
        RequireTyped<UpdateCollectionFn>("EspUpdateCollection");
    if (create_fn == nullptr || update_fn == nullptr || !client_handle_ ||
        !Adopt("EspCreateCollection", created, [&](void** slot) {
          return create_fn(AsSharedWrapper(client_handle_), desc.data(), slot);
        })) {
      return false;
    }
    collections_.push_back(created);
    binary_storage_.push_back({0x65, 0x73, 0x70});
    CollectionBinaryUpdateEntry entry{};
    entry.byte_count =
        static_cast<std::uint32_t>(binary_storage_.back().size());
    entry.data = binary_storage_.back().data();
    binary_entries_.push_back(entry);
    const EspResult update_result =
        update_fn(AsSharedWrapper(created), 0, 1, &binary_entries_.back());
    Record("EspUpdateCollection", update_result);
    if (Failed(update_result)) {
      return false;
    }
  } else if (!CreateStringCollection(L"esptool-collection-entry", created) ||
             !created) {
    return false;
  }
  Guid created_id{};
  if (const auto fn = RequireTyped<GetCollectionIdFn>("EspGetCollectionId")) {
    const EspResult result = fn(AsSharedWrapper(created), &created_id);
    Record("EspGetCollectionId", result);
    if (Succeeded(result)) {
      const auto bytes = std::bit_cast<std::array<std::uint8_t, 16>>(created_id);
      std::printf("collection-id %s\n", text::FormatGuid(bytes).c_str());
    }
  }
  if (const auto fn =
          RequireTyped<GetCollectionTypeFn>("EspGetCollectionType")) {
    int type = 0;
    Record("EspGetCollectionType", fn(AsSharedWrapper(created), &type));
    std::printf("collection-type %d\n", type);
  }
  if (const auto fn = RequireTyped<EnumerateCollectionEntriesFn>(
          "EspEnumerateCollectionEntries")) {
    int count = 0;
    void* entries = nullptr;
    Record("EspEnumerateCollectionEntries",
           fn(AsSharedWrapper(created), &count, &entries));
    std::printf("collection-entries %d\n", count);
    FreeEspBuffer(entries);
  }
  bool ok = true;
  if (enum_ids) {
    int count = 0;
    std::vector<Guid> ids;
    if (!EnumerateCollectionIds(lifetime, count, &ids)) {
      ok = false;
    }
  }
  if (do_open) {
    const Guid target = open_id != nullptr ? *open_id : created_id;
    Collection opened{};
    if (!OpenNamedCollection(target, opened)) {
      ok = false;
    }
  }
  return ok;
}

bool EspSession::QueryFromNotification() {
  if (!notification_ || !client_handle_) {
    return false;
  }
  const auto* bytes = static_cast<const std::byte*>(notification_.get());
  NotificationKeys keys;
  if (!DecodeNotificationKeys(bytes, keys)) {
    Warn("QueryFromNotification could not decode notification keys");
    return false;
  }

  ObjectReference natural;
  bool created = false;
  if (IsFoIoEvent(keys.event_type)) {
    std::wstring path;
    if (!keys.name.empty() && LooksLikeNtDevicePath(keys.name)) {
      path = text::ToUtf16(keys.name);
    } else if (!keys.name.empty()) {
      std::string value = keys.name;
      if (value.front() == '\\' && !LooksLikeNtPathPrefix(value)) {
        value.insert(0, std::string(kNtPathPrefix));
      }
      path = ExpandFilterValue(value);
    }
    if (!path.empty()) {
      created = CreatePathReference("EspCreateFileReferenceByPath", path,
                                    natural);
    }
    if (!created && !notify_fallback_path_.empty()) {
      created = CreatePathReference("EspCreateFileReferenceByPath",
                                    notify_fallback_path_, natural);
    }
    if (!created) {
      Warn("QueryFromNotification Fo event has no usable path");
      return false;
    }
  } else {
    if (keys.pid == 0) {
      keys.pid = static_cast<std::uint32_t>(notify_fallback_pid_);
    }
    if (keys.pid == 0) {
      Warn("QueryFromNotification process event has pid 0");
      return false;
    }
    created = CreatePidReference("EspCreateProcessReference",
                                 static_cast<int>(keys.pid), natural);
  }
  if (!created) {
    return false;
  }

  EventObject view;
  if (!UnwrapReference(natural, view)) {
    CloseReference(natural);
    return true;
  }
  int object_type = 0;
  (void)GetEventObjectType(view, object_type);
  std::uint64_t event_object_id = 0;
  (void)GetEventObjectId(view, event_object_id);

  ObjectReference by_id;
  EventObject by_id_view;
  ObjectReference* context_ref = &natural;
  EventObject query_view = view;
  if (event_object_id != 0 && CreateEventObjectById(event_object_id, by_id) &&
      UnwrapReference(by_id, by_id_view)) {
    query_view = by_id_view;
    context_ref = &by_id;
  }

  for (const auto& [event_type, recipe] : notify_queries_) {
    if (event_type != 0 && keys.event_type != 0 &&
        event_type != keys.event_type) {
      continue;
    }
    if (!recipe.kind.empty() && recipe.kind != "event") {
      if (!recipe.properties.empty()) {
        (void)QueryKind(recipe.kind, query_view, recipe.properties.data(),
                        static_cast<unsigned>(recipe.properties.size()));
      }
    }
    if (!recipe.kind.empty()) {
      for (unsigned property : recipe.properties) {
        std::uint32_t supported = 0;
        (void)IsPropertySupported(recipe.kind, property, supported);
      }
      if (recipe.kind == "event" && recipe.properties.empty()) {
        std::uint32_t supported = 0;
        (void)IsPropertySupported("event", 1, supported);
      }
    }
    if (recipe.context_set) {
      (void)SetEventObjectContextKey(*context_ref);
    }
    if (recipe.context_enum) {
      (void)EnumerateEventObjectContextKeys(*context_ref);
    }
  }

  CloseReference(by_id);
  CloseReference(natural);
  return true;
}

}  // namespace esptool::esp
