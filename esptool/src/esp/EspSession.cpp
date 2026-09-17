#include "esp/EspSession.h"

#include <Windows.h>
#include <combaseapi.h>

#include <array>
#include <bit>
#include <chrono>
#include <cstdio>
#include <format>
#include <limits>
#include <string>
#include <string_view>
#include <thread>

#include "esp/EspCatalog.h"
#include "esp/EspMemoryView.h"
#include "esp/EspNotifyFormat.h"
#include "esp/EspStatus.h"
#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool::esp {

EspSession::~EspSession() { Disconnect(); }

void EspSession::Record(std::string step, EspResult result,
                        std::optional<bool> ok) {
  StepResult entry;
  entry.step = std::move(step);
  entry.result = result;
  entry.ok = ok.value_or(Succeeded(result));
  steps_.push_back(std::move(entry));
}

void EspSession::Warn(std::string message) {
  warnings_.push_back(std::move(message));
}

const ExportDescriptor* EspSession::Require(std::string_view name) {
  const ExportDescriptor* descriptor = api_.Find(name);
  if (descriptor == nullptr || descriptor->address == nullptr) {
    Warn(std::format("export not available: {}", name));
    return nullptr;
  }
  return descriptor;
}

bool EspSession::Connect(const model::ClientSpec& client) {
  const auto connect_fn = RequireTyped<ConnectClientFn>("EspConnectClient");
  const auto register_fn = RequireTyped<RegisterClientFn>("EspRegisterClient");
  if (connect_fn == nullptr || register_fn == nullptr) {
    return false;
  }

  client_id_ = client.guid;
  if (IsNull(client_id_)) {
    GUID generated{};
    const HRESULT generated_hr = CoCreateGuid(&generated);
    if (FAILED(generated_hr)) {
      Record("EspConnectClient", static_cast<EspResult>(generated_hr));
      Warn("could not generate a client GUID");
      return false;
    }
    static_assert(sizeof(GUID) == sizeof(Guid));
    client_id_ = std::bit_cast<Guid>(generated);
  }

  const std::wstring name =
      text::ToUtf16(client.name.empty() ? kDefaultClientName : client.name);
  unsigned altitude_base = kDefaultClientAltitudeValue;
  if (!client.altitude.empty()) {
    std::uint64_t parsed = 0;
    if (text::ParseUnsigned(client.altitude, parsed) && parsed != 0 &&
        parsed <= std::numeric_limits<unsigned>::max()) {
      altitude_base = static_cast<unsigned>(parsed);
    }
  }
  std::wstring altitude = std::to_wstring(altitude_base);
  ClientRegisterDescriptor descriptor{};
  descriptor.id = client_id_;
  descriptor.name = name.c_str();

  EspResult register_result = kFail;
  for (unsigned attempt = 0; attempt < kAltitudeCollisionTries; ++attempt) {
    if (attempt > 0) {
      const unsigned bumped =
          (altitude_base == 0 ? kDefaultClientAltitudeValue : altitude_base) +
          attempt * kAltitudeCollisionStep;
      altitude = std::to_wstring(bumped);
    }
    descriptor.altitude = altitude.c_str();
    register_result = register_fn(&descriptor);
    if (register_result == kOk) {
      break;
    }
    if (register_result != kAlreadyExists) {
      break;
    }
    if (Log::WouldLog(LogLevel::Debug)) {
      Log::Debug(std::format(
          "EspRegisterClient: collision at altitude {}, retrying with bump",
          text::ToUtf8(altitude)));
    }
  }
  Record("EspRegisterClient", register_result);
  if (register_result != kOk) {
    return false;
  }
  registered_this_session_ = true;

  if (!Adopt("EspConnectClient", client_handle_,
             [&](void** slot) { return connect_fn(&client_id_, slot); })) {
    UnregisterIfOwned();
    return false;
  }
  return true;
}

bool EspSession::ConnectExisting(const Guid& id) {
  const auto connect_fn = RequireTyped<ConnectClientFn>("EspConnectClient");
  if (connect_fn == nullptr || IsNull(id)) {
    return false;
  }
  client_id_ = id;
  registered_this_session_ = false;
  return Adopt("EspConnectClient", client_handle_,
               [&](void** slot) { return connect_fn(&client_id_, slot); });
}

void EspSession::Disconnect() {
  if (notification_) {
    if (const auto fn =
            RequireTyped<FreeNotificationFn>("EspFreeEventNotification")) {
      fn(notification_.abi());
    }
    notification_.reset();
  }
  CloseOwned(filters_, "EspCloseFilter");
  CloseOwned(rules_, "EspCloseRule");
  CloseOwned(object_refs_, "EspCloseEventObjectReference");
  CloseOwned(collections_, "EspCloseCollection");
  named_collections_.clear();
  notify_queries_.clear();
  CloseOne(queue_handle_, "EspCloseEventQueue");
  CloseOne(client_handle_, "EspDisconnectClient");
  fo_io_configs_.clear();
  numeric_blobs_.clear();
  bool_blobs_.clear();
  file_path_blobs_.clear();
  filter_blobs_.clear();
  filter_strings_.clear();
  collection_blobs_.clear();
  collection_entries_.clear();
  event_modify_blobs_.clear();
  access_masks_.clear();
  subrule_handles_.clear();
  UnregisterIfOwned();
}

void EspSession::UnregisterIfOwned() {
  if (!registered_this_session_ || !unregister_on_disconnect_) {
    return;
  }
  if (const auto fn = RequireTyped<UnregisterClientFn>("EspUnregisterClient")) {
    Record("EspUnregisterClient", fn(&client_id_));
  }
  registered_this_session_ = false;
}

bool EspSession::CreateQueue() {
  const auto fn = RequireTyped<CreateEventQueueFn>("EspCreateEventQueue");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  EventQueueDescriptor descriptor{};
  return Adopt("EspCreateEventQueue", queue_handle_, [&](void** slot) {
    return fn(AsSharedWrapper(client_handle_), &descriptor, slot);
  });
}

bool EspSession::OpenQueue(const Guid& queue_id) {
  const auto fn = RequireTyped<OpenEventQueueFn>("EspOpenEventQueue");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  Guid mutable_id = queue_id;
  return Adopt("EspOpenEventQueue", queue_handle_, [&](void** slot) {
    return fn(AsSharedWrapper(client_handle_), &mutable_id, slot);
  });
}

bool EspSession::ConnectQueueToIocp(HANDLE completion_port) {
  const auto fn =
      RequireTyped<ConnectQueueIocpFn>("EspConnectEventQueueWithIocp");
  if (fn == nullptr || !queue_handle_) {
    return false;
  }
  void* returned_port = nullptr;
  const EspResult result =
      fn(AsSharedWrapper(queue_handle_), static_cast<void*>(completion_port),
         &returned_port);
  Record("EspConnectEventQueueWithIocp", result);
  return Succeeded(result);
}

bool EspSession::CreateIocpQueue(HANDLE& port) {
  const auto fn =
      RequireTyped<ConnectQueueIocpFn>("EspConnectEventQueueWithIocp");
  if (fn == nullptr || !queue_handle_) {
    return false;
  }
  void* raw = nullptr;
  const EspResult result = fn(AsSharedWrapper(queue_handle_), nullptr, &raw);
  Record("EspConnectEventQueueWithIocp", result);
  port = static_cast<HANDLE>(raw);
  return Succeeded(result) && raw != nullptr;
}

bool EspSession::EnumerateClients(int& count, std::vector<Guid>* ids) {
  const auto fn =
      RequireTyped<EnumerateClientsFn>("EspEnumerateRegisteredClients");
  if (fn == nullptr) {
    return false;
  }
  count = 0;
  void* list = nullptr;
  const EspResult result = fn(&count, &list);
  Record("EspEnumerateRegisteredClients", result);
  if (Succeeded(result) && ids != nullptr && count > 0 && list != nullptr) {
    const auto* first = static_cast<const Guid*>(list);
    ids->assign(first, first + count);
  }
  return Succeeded(result);
}

bool EspSession::UnregisterClientId(const Guid& id) {
  const auto fn = RequireTyped<UnregisterClientFn>("EspUnregisterClient");
  if (fn == nullptr) {
    return false;
  }
  Guid mutable_id = id;
  const EspResult result = fn(&mutable_id);
  Record("EspUnregisterClient", result);
  return Succeeded(result);
}

bool EspSession::EnumerateRuleIds(int lifetime, int& count) {
  const auto fn = RequireTyped<EnumerateRuleIdsFn>("EspEnumerateRuleIds");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  count = 0;
  void* list = nullptr;
  const EspResult result =
      fn(AsSharedWrapper(client_handle_), lifetime, &count, &list);
  Record("EspEnumerateRuleIds", result);
  return Succeeded(result);
}

bool EspSession::EnumerateAllRules(int& count) {
  const auto fn =
      RequireTyped<EnumerateAllRulesFn>("EspEnumerateAllRulesForClient");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  count = 0;
  void* list = nullptr;
  const EspResult result = fn(AsSharedWrapper(client_handle_), &count, &list);
  Record("EspEnumerateAllRulesForClient", result);
  return Succeeded(result);
}

bool EspSession::RemoveAllRules() {
  const auto fn = RequireTyped<RemoveAllRulesFn>("EspRemoveAllRulesForClient");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  const EspResult result = fn(AsSharedWrapper(client_handle_));
  Record("EspRemoveAllRulesForClient", result);
  return Succeeded(result);
}

bool EspSession::RemoveRulesForLifetime(int lifetime) {
  const auto fn = RequireTyped<RemoveRulesFn>("EspRemoveRulesForClient");
  if (fn == nullptr || !client_handle_) {
    return false;
  }
  const EspResult result = fn(AsSharedWrapper(client_handle_), lifetime);
  Record("EspRemoveRulesForClient", result);
  return Succeeded(result);
}

bool EspSession::GetQueueId(Guid& id) {
  const auto fn = RequireTyped<GetEventQueueIdFn>("EspGetEventQueueId");
  if (fn == nullptr || !queue_handle_) {
    return false;
  }
  const EspResult result = fn(AsSharedWrapper(queue_handle_), &id);
  Record("EspGetEventQueueId", result);
  return Succeeded(result);
}

bool EspSession::ConnectQueueToCallback(QueueNotifyAbi callback,
                                        EspSession* context) {
  const auto fn =
      RequireTyped<ConnectQueueCallbackFn>("EspConnectEventQueueWithCallback");
  if (fn == nullptr || !queue_handle_) {
    return false;
  }
  const EspResult result = fn(AsSharedWrapper(queue_handle_), 0,
                              reinterpret_cast<void*>(callback), context);
  Record("EspConnectEventQueueWithCallback", result);
  return Succeeded(result);
}

bool EspSession::ArmNotification() {
  const auto allocate_fn =
      RequireTyped<AllocateNotificationFn>("EspAllocateEventNotification");
  const auto arm_fn =
      RequireTyped<ArmNotificationFn>("EspArmEventNotification");
  if (allocate_fn == nullptr || arm_fn == nullptr || !queue_handle_) {
    return false;
  }
  if (!notification_) {
    void* notification = allocate_fn();
    if (notification == nullptr) {
      Record("EspAllocateEventNotification", kOutOfMemory);
      return false;
    }
    notification_ = Notification{notification};
    Record("EspAllocateEventNotification", kOk);
  }

  const EspResult result =
      arm_fn(AsSharedWrapper(queue_handle_), notification_.abi());
  const bool armed = Succeeded(result) || result == kIoPending;
  Record("EspArmEventNotification", result, armed);
  return armed;
}

bool EspSession::CompleteNotification() {
  const auto fn =
      RequireTyped<CompleteNotificationFn>("EspCompleteEventNotification");
  if (fn == nullptr || !notification_) {
    return false;
  }
  const EspResult result = fn(notification_.abi());
  Record("EspCompleteEventNotification", result);
  return Succeeded(result);
}

bool EspSession::ClearQueue() {
  const auto fn = RequireTyped<ClearEventQueueFn>("EspClearEventQueue");
  if (fn == nullptr || !queue_handle_) {
    return false;
  }
  const EspResult result = fn(AsSharedWrapper(queue_handle_));
  Record("EspClearEventQueue", result);
  return Succeeded(result);
}

bool EspSession::CreateStringCollection(const std::wstring& value,
                                        Collection& out) {
  const auto create_fn =
      RequireTyped<CreateCollectionFn>("EspCreateCollection");
  const auto update_fn =
      RequireTyped<UpdateCollectionFn>("EspUpdateCollection");
  if (create_fn == nullptr || update_fn == nullptr || !client_handle_ ||
      value.empty()) {
    return false;
  }
  alignas(8) std::array<std::uint8_t, 32> collection_desc{};
  WriteU32At(collection_desc.data(), 16, kCollectionTypeString);
  WriteU32At(collection_desc.data(), 20, kCollectionStringSubtype);
  if (!Adopt("EspCreateCollection", out, [&](void** slot) {
        return create_fn(AsSharedWrapper(client_handle_),
                         collection_desc.data(), slot);
      })) {
    return false;
  }
  collections_.push_back(out);
  filter_strings_.push_back(value);
  CollectionUpdateEntry entry{};
  entry.operation = kCollectionUpdateAdd;
  const std::uint64_t bytes = filter_strings_.back().size() * sizeof(wchar_t);
  if (bytes == 0 || bytes > kMaxUtf16Bytes) {
    return false;
  }
  entry.utf16_bytes = static_cast<std::uint16_t>(bytes);
  entry.text = filter_strings_.back().c_str();
  collection_entries_.push_back(entry);
  const EspResult update_result =
      update_fn(AsSharedWrapper(out), 0, 1, &collection_entries_.back());
  Record("EspUpdateCollection", update_result);
  if (Failed(update_result)) {
    return false;
  }
  return true;
}

bool EspSession::QueryAllProperties() {
  bool any = false;
  for (const char* name : kPropertyQueryExports) {
    const auto fn = RequireTyped<QueryPropertiesFn>(name);
    if (fn == nullptr) {
      continue;
    }
    void* buffer = nullptr;
    const EspResult result =
        fn(AsSharedWrapper(client_handle_), 0, nullptr, &buffer);
    Record(name, result);
    std::printf("query-smoke %s 0x%08x (count 0, client handle)\n", name,
                static_cast<unsigned>(result));
    FreeEspBuffer(buffer);
    any = true;
  }
  return any;
}

// QueryFromNotification is implemented in EspRefs.cpp (natural-key create,
// unwrap, EspGetEventObjectId, then EspCreateEventObjectReferenceById).

bool EspSession::OpenQueueById(const Guid& queue_id) {
  return OpenQueue(queue_id);
}

void EspSession::CloseQueue() { CloseOne(queue_handle_, "EspCloseEventQueue"); }

bool EspSession::ExerciseCollections() {
  const auto close_fn = RequireTyped<CloseCollectionFn>("EspCloseCollection");
  if (close_fn == nullptr) {
    return false;
  }
  Collection collection{};
  if (!CreateStringCollection(L"*{65535}", collection) ||
      !collection) {
    return false;
  }
  if (const auto fn = RequireTyped<EnumerateCollectionEntriesFn>(
          "EspEnumerateCollectionEntries")) {
    int count = 0;
    void* entries = nullptr;
    Record("EspEnumerateCollectionEntries",
           fn(AsSharedWrapper(collection), &count, &entries));
    FreeEspBuffer(entries);
  }
  if (const auto fn =
          RequireTyped<GetCollectionTypeFn>("EspGetCollectionType")) {
    int type = 0;
    Record("EspGetCollectionType", fn(AsSharedWrapper(collection), &type));
  }
  if (const auto fn = RequireTyped<GetCollectionIdFn>("EspGetCollectionId")) {
    Guid id{};
    Record("EspGetCollectionId", fn(AsSharedWrapper(collection), &id));
  }
  Record("EspCloseCollection", close_fn(AsSharedWrapper(collection)));
  collections_.clear();
  return true;
}

bool EspSession::ExerciseContextKeys() {
  const auto set_key_fn =
      RequireTyped<SetContextKeyFn>("EspSetClientContextKey");
  const auto enumerate_fn =
      RequireTyped<EnumerateContextKeysFn>("EspEnumerateAllClientContextKeys");
  if (set_key_fn == nullptr || enumerate_fn == nullptr) {
    return false;
  }
  std::array<std::uint32_t, kContextKeyDwords> key_payload{};
  Record("EspSetClientContextKey",
         set_key_fn(AsSharedWrapper(client_handle_), key_payload.data()));

  int count = 0;
  void* keys = nullptr;
  Record("EspEnumerateAllClientContextKeys",
         enumerate_fn(AsSharedWrapper(client_handle_), &count, &keys));
  return true;
}

void EspSession::OnQueueNotification(void* notification, void* context) {
  if (context != nullptr) {
    static_cast<EspSession*>(context)->HandleQueueNotification(
        Notification{notification});
  }
}

void EspSession::HandleQueueNotification(const Notification notification) {
  if (!notification) {
    return;
  }
  notification_ = notification;
  if (pump_event_ != nullptr) {
    SetEvent(pump_event_);
  }
}

bool EspSession::ConsumeNotification(HANDLE wait_event,
                                     unsigned long long deadline,
                                     unsigned max_notifications) {
  const ULONGLONG now = GetTickCount64();
  if (now >= deadline) {
    return false;
  }
  const DWORD remaining = static_cast<DWORD>(deadline - now);
  if (WaitForSingleObject(wait_event, remaining) != WAIT_OBJECT_0) {
    return false;
  }

  return EmitCompleteAndRearm(max_notifications);
}

bool EspSession::EmitCompleteAndRearm(unsigned max_notifications) {
  const auto* bytes = static_cast<const std::byte*>(notification_.get());
  ++notifications_received_;
  const std::string line =
      bytes == nullptr
          ? FormatEmptyNotificationLine(notifications_received_)
          : FormatQueueNotification(bytes, notifications_received_);
  Log::Info(line);
  Record("notification", kOk);
  if (!notify_queries_.empty()) {
    (void)QueryFromNotification();
  }

  if (!CompleteNotification()) {
    return false;
  }
  if (notifications_received_ >= max_notifications) {
    return false;
  }
  return ArmNotification();
}

void EspSession::PumpNotifications(unsigned milliseconds,
                                   unsigned max_notifications) {
  notifications_received_ = 0;
  if (!queue_handle_) {
    // A non-queue document (deny, suppress, cancel) has no notification pump,
    // but the hold still has to be honored. Returning here disconnects the
    // client immediately, which removes the transient rule before a trigger can
    // reach it. Measured on build 10.0.29667: `--worker monitor` returned in
    // under a second for an `action="deny"` document and the rule never
    // enforced, while `--worker rules --duration` did enforce it.
    Warn(
        "PumpNotifications has no created event queue; holding without "
        "pumping");
    if (milliseconds > 0) {
      std::this_thread::sleep_for(std::chrono::milliseconds{milliseconds});
    }
    return;
  }
  if (!ConnectQueueToCallback(&OnQueueNotification, this)) {
    return;
  }

  UniqueHandle event(CreateEventW(nullptr, FALSE, FALSE, nullptr));
  if (!event) {
    Warn("could not create the notification wait event");
    return;
  }
  pump_event_ = event.get();

  if (!ArmNotification()) {
    pump_event_ = nullptr;
    return;
  }

  const ULONGLONG deadline = GetTickCount64() + milliseconds;
  while (notifications_received_ < max_notifications) {
    if (!ConsumeNotification(event.get(), deadline, max_notifications)) {
      break;
    }
  }

  pump_event_ = nullptr;
  Log::Info(
      std::format("notification pump received {}", notifications_received_));
}

void EspSession::PumpNotificationsIocp(unsigned milliseconds,
                                       unsigned max_notifications) {
  notifications_received_ = 0;
  if (!queue_handle_) {
    Warn("PumpNotificationsIocp requires a created event queue");
    return;
  }
  HANDLE port{};
  if (!CreateIocpQueue(port)) {
    return;
  }
  if (!ArmNotification()) {
    return;
  }
  const ULONGLONG deadline = GetTickCount64() + milliseconds;
  while (notifications_received_ < max_notifications) {
    const ULONGLONG now = GetTickCount64();
    if (now >= deadline) {
      break;
    }
    DWORD bytes = 0;
    ULONG_PTR key = 0;
    LPOVERLAPPED overlapped = nullptr;
    const DWORD wait = static_cast<DWORD>(deadline - now);
    if (!GetQueuedCompletionStatus(static_cast<HANDLE>(port), &bytes, &key,
                                   &overlapped, wait)) {
      break;
    }
    if (!notification_) {
      notification_ = Notification{overlapped};
    }
    if (!EmitCompleteAndRearm(max_notifications)) {
      break;
    }
  }
  Log::Info(std::format("iocp pump received {}", notifications_received_));
}

EspResult EspSession::CallRaw(
    const ExportDescriptor& descriptor,
    const std::array<std::uintptr_t, EspApi::kMaxArity>& arguments) {
  const EspResult result =
      static_cast<EspResult>(api_.Invoke(descriptor, arguments));
  Record("call:" + descriptor.name, result);
  return result;
}

}  // namespace esptool::esp
