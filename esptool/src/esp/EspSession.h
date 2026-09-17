#pragma once

#include <array>
#include <cstdint>
#include <deque>
#include <optional>
#include <string>
#include <string_view>
#include <utility>
#include <vector>

#include "esp/EspApi.h"
#include "esp/EspCall.h"
#include "esp/EspRefAbi.h"
#include "esp/EspStatus.h"
#include "esp/EspTypes.h"
#include "model/RuleDocument.h"
#include "util/UniqueHandle.h"

namespace esptool::esp {

// Result of one session operation.
struct StepResult {
  std::string step;
  EspResult result = 0;
  bool ok = false;
};

// Outcome of InstallRules. Distinguishes a complete install from a partial one
// so a caller cannot read "some rules were committed" as "every rule is armed".
enum class InstallStatus {
  Failed,    // Nothing usable was committed.
  Partial,   // Some rules were committed; at least one rule was refused.
  Complete,  // Every rule in the document was committed.
};

// Owns a client, an event queue, and the rule handles created during a run.
class EspSession {
 public:
  explicit EspSession(const EspApi& api) : api_(api) {}
  ~EspSession();

  EspSession(const EspSession&) = delete;
  EspSession& operator=(const EspSession&) = delete;
  EspSession(EspSession&&) = delete;
  EspSession& operator=(EspSession&&) = delete;

  // Registers the client identity (opcode 1), then opens a session
  // (opcode 3). Returns true when the client handle is non-null.
  [[nodiscard]] bool Connect(const model::ClientSpec& client);
  // Connects to an existing registered client identity (opcode 3) without
  // registering. Does not own registration lifecycle.
  [[nodiscard]] bool ConnectExisting(const Guid& id);
  void Disconnect();

  using QueueNotifyAbi = void (*)(void* notification, void* context);

  [[nodiscard]] bool CreateQueue();
  [[nodiscard]] bool OpenQueue(const Guid& queue_id);
  [[nodiscard]] bool ConnectQueueToIocp(HANDLE completion_port);
  [[nodiscard]] bool ConnectQueueToCallback(QueueNotifyAbi callback,
                                            EspSession* context);
  [[nodiscard]] bool ArmNotification();
  [[nodiscard]] bool CompleteNotification();
  [[nodiscard]] bool ClearQueue();

  // Builds the predicate tree for each rule and installs the batch. A per-rule
  // failure does not drop the batch: the rules that were created are committed,
  // and the status distinguishes a complete install from a partial one.
  [[nodiscard]] InstallStatus InstallRules(const model::RuleDocument& document);

  [[nodiscard]] bool QueryAllProperties();
  [[nodiscard]] bool QueryFromNotification();
  [[nodiscard]] bool QueryKind(std::string_view kind, EventObject view,
                               const unsigned* ids, unsigned count);
  [[nodiscard]] bool IsPropertySupported(std::string_view kind,
                                         unsigned property_id,
                                         std::uint32_t& supported);
  [[nodiscard]] bool CreatePidReference(std::string_view export_name, int pid,
                                        ObjectReference& out);
  [[nodiscard]] bool CreatePathReference(std::string_view export_name,
                                         std::wstring_view path,
                                         ObjectReference& out);
  [[nodiscard]] bool CreateDesktopReference(std::wstring_view name,
                                            ObjectReference& out);
  [[nodiscard]] bool CreateVolumeReference(const Guid& volume,
                                           ObjectReference& out);
  [[nodiscard]] bool CreateFileIdReference(const Guid& volume,
                                           const FileIdDescriptorRaw& file_id,
                                           ObjectReference& out);
  [[nodiscard]] bool CreateStreamByIdReference(
      const Guid& volume, const FileIdDescriptorRaw& file_id,
      const wchar_t* stream_name, ObjectReference& out);
  [[nodiscard]] bool CreateEventObjectById(std::uint64_t event_object_id,
                                           ObjectReference& out);
  [[nodiscard]] bool UnwrapReference(const ObjectReference& ref,
                                     EventObject& view);
  [[nodiscard]] bool DuplicateReference(const ObjectReference& ref,
                                        ObjectReference& out);
  [[nodiscard]] bool GetEventObjectId(const EventObject& view,
                                      std::uint64_t& id);
  [[nodiscard]] bool GetEventObjectType(const EventObject& view, int& type);
  [[nodiscard]] bool SetEventObjectContextKey(const ObjectReference& ref);
  [[nodiscard]] bool EnumerateEventObjectContextKeys(
      const ObjectReference& ref);
  void CloseReference(ObjectReference& ref);
  [[nodiscard]] bool OpenNamedCollection(const Guid& id, Collection& out);
  [[nodiscard]] bool EnumerateCollectionIds(int lifetime, int& count,
                                            std::vector<Guid>* ids);
  [[nodiscard]] bool InstallDocumentCollections(
      const model::RuleDocument& document);
  [[nodiscard]] Collection FindNamedCollection(std::string_view name) const;
  void FreeEspBuffer(void* buffer);
  [[nodiscard]] bool ExerciseCollections();
  [[nodiscard]] bool ExerciseCollectionsExtended(int lifetime, bool enum_ids,
                                                 bool do_open,
                                                 const Guid* open_id,
                                                 std::uint32_t create_type);
  [[nodiscard]] bool ExerciseContextKeys();
  [[nodiscard]] bool OpenQueueById(const Guid& queue_id);
  void CloseQueue();

  // Connects the queue in callback mode, arms a read, and waits for
  // notifications for the supplied duration in milliseconds.
  void PumpNotifications(unsigned milliseconds, unsigned max_notifications);
  void PumpNotificationsIocp(unsigned milliseconds, unsigned max_notifications);

  void SetUnregisterOnDisconnect(bool value) noexcept {
    unregister_on_disconnect_ = value;
  }
  void SetNotifyFallbackPid(int pid) noexcept { notify_fallback_pid_ = pid; }
  void SetNotifyFallbackPath(std::wstring path) {
    notify_fallback_path_ = std::move(path);
  }
  void SetIocpPump(bool value) noexcept { iocp_pump_ = value; }
  [[nodiscard]] bool IocpPump() const noexcept { return iocp_pump_; }

  // Opt-in for the espclient.dll EventModify::from_ffi compat patch. When set,
  // InstallRules can install an enforcing (deny) rule for the driver-ready
  // event types the unpatched client refuses. See esp/EspEnforceCompat.h.
  void SetEnforceCompat(bool value) noexcept { enforce_compat_ = value; }

  [[nodiscard]] bool EnumerateClients(int& count,
                                      std::vector<Guid>* ids = nullptr);
  [[nodiscard]] bool UnregisterClientId(const Guid& id);
  [[nodiscard]] bool EnumerateRuleIds(int lifetime, int& count);
  [[nodiscard]] bool EnumerateAllRules(int& count);
  [[nodiscard]] bool RemoveAllRules();
  [[nodiscard]] bool RemoveRulesForLifetime(int lifetime);
  [[nodiscard]] bool GetQueueId(Guid& id);
  [[nodiscard]] bool CreateIocpQueue(HANDLE& port);

  [[nodiscard]] unsigned NotificationsReceived() const noexcept {
    return notifications_received_;
  }

  [[nodiscard]] const std::vector<StepResult>& Steps() const noexcept {
    return steps_;
  }
  [[nodiscard]] const std::vector<std::string>& Warnings() const noexcept {
    return warnings_;
  }
  [[nodiscard]] Client ClientHandle() const noexcept { return client_handle_; }
  [[nodiscard]] Queue QueueHandle() const noexcept { return queue_handle_; }
  [[nodiscard]] Notification NotificationHandle() const noexcept {
    return notification_;
  }
  [[nodiscard]] const Guid& ClientId() const noexcept { return client_id_; }

  // Invokes a single export with the supplied arguments and records the
  // result. Used by the exhaustion sweep.
  EspResult CallRaw(
      const ExportDescriptor& descriptor,
      const std::array<std::uintptr_t, EspApi::kMaxArity>& arguments);

 private:
  void Record(std::string step, EspResult result, std::optional<bool> ok = {});
  void Warn(std::string message);
  [[nodiscard]] const ExportDescriptor* Require(std::string_view name);

  template <class Fn>
  [[nodiscard]] Fn RequireTyped(std::string_view name) {
    const ExportDescriptor* descriptor = Require(name);
    return descriptor != nullptr ? reinterpret_cast<Fn>(descriptor->address)
                                 : nullptr;
  }

  // produce() must write the FFI out-slot, then return. Evaluating the
  // handle in the same argument list as the FFI call can copy nullptr
  // before the export fills it (argument evaluation is unsequenced).
  template <typename Tag, typename Produce>
  [[nodiscard]] bool Adopt(std::string_view step, Opaque<Tag>& out,
                           Produce&& produce) {
    void* raw = nullptr;
    const EspResult result = produce(&raw);
    Record(std::string(step), result);
    if (Failed(result) || raw == nullptr) {
      out.reset();
      return false;
    }
    out = Opaque<Tag>{raw};
    return true;
  }
  template <typename Tag>
  void CloseOwned(std::vector<Opaque<Tag>>& handles, std::string_view closer) {
    for (Opaque<Tag>& handle : handles) {
      if (!handle) {
        continue;
      }
      if (const auto fn = RequireTyped<CloseOutFn>(closer)) {
        fn(AsSharedWrapper(handle));
      }
    }
    handles.clear();
  }

  template <typename Tag>
  void CloseOne(Opaque<Tag>& handle, std::string_view closer) {
    if (!handle) {
      return;
    }
    if (const auto fn = RequireTyped<CloseOutFn>(closer)) {
      fn(AsSharedWrapper(handle));
    }
    handle.reset();
  }

  [[nodiscard]] bool CreateStringCollection(const std::wstring& value,
                                            Collection& collection);
  [[nodiscard]] EspResult CreateLeafFilter(const model::FilterNode& node,
                                           Filter& out_filter);
  [[nodiscard]] EspResult CreateFilterTree(const model::FilterNode& node,
                                           Filter& out_filter);
  [[nodiscard]] EspResult CreateBinaryFilter(model::FilterKind kind,
                                             Filter left, Filter right,
                                             Filter& out_filter);
  [[nodiscard]] EspResult CreateNotFilter(Filter child, Filter& out_filter);
  [[nodiscard]] bool TryBuildRuleFilter(const model::RuleSpec& spec,
                                        Filter& filter);
  void AttachFilterToDescriptor(RuleDescriptor& descriptor,
                                const model::RuleSpec& spec, Filter filter);
  [[nodiscard]] bool SubmitRuleBatch(
      const std::vector<RuleUpdateEntry>& entries);

  // Applies the enforce-compat patch at most once per session and caches the
  // outcome. Returns true when the patch is in effect.
  [[nodiscard]] bool EnsureEnforceCompatPatch();

  static void OnQueueNotification(void* notification, void* context);
  void HandleQueueNotification(const Notification notification);
  [[nodiscard]] bool ConsumeNotification(HANDLE wait_event,
                                         unsigned long long deadline,
                                         unsigned max_notifications);
  [[nodiscard]] bool EmitCompleteAndRearm(unsigned max_notifications);
  [[nodiscard]] static bool IsEmptyFilter(
      const model::FilterNode& node) noexcept;
  [[nodiscard]] static std::uint32_t ResolveActionSelector(
      std::uint64_t action) noexcept;
  void UnregisterIfOwned();

  const EspApi& api_;
  // True only after EspRegisterClient returns S_OK. ALREADY_EXISTS must not
  // unregister.
  bool registered_this_session_ = false;
  Client client_handle_{};
  Queue queue_handle_{};
  Notification notification_{};
  HANDLE pump_event_ = nullptr;
  Guid client_id_{};
  unsigned notifications_received_ = 0;
  std::vector<Rule> rules_;
  std::vector<Filter> filters_;
  std::vector<Collection> collections_;
  std::vector<std::pair<std::string, Collection>> named_collections_;
  std::vector<ObjectReference> object_refs_;
  std::vector<std::pair<std::uint32_t, model::QueryRecipe>> notify_queries_;
  std::deque<std::wstring> path_storage_;
  std::deque<FileIdDescriptorRaw> file_id_storage_;
  std::deque<std::vector<std::uint8_t>> binary_storage_;
  std::deque<CollectionIntegerUpdateEntry> integer_entries_;
  std::deque<CollectionBinaryUpdateEntry> binary_entries_;
  std::deque<std::wstring> filter_strings_;
  std::deque<StringComparandRaw> filter_blobs_;
  std::deque<NumericComparandRaw> numeric_blobs_;
  std::deque<BoolComparandRaw> bool_blobs_;
  std::deque<FilePathComparandRaw> file_path_blobs_;
  std::deque<CollectionComparandRaw> collection_blobs_;
  std::deque<CollectionUpdateEntry> collection_entries_;
  std::deque<EventModifyBlob> event_modify_blobs_;
  std::deque<AccessMaskModification> access_masks_;
  std::vector<void*> subrule_handles_;
  std::deque<FoIoConfigBlob> fo_io_configs_;
  std::deque<std::vector<std::int32_t>> dynamic_queries_;
  PropertyQueryStore query_store_{};
  bool unregister_on_disconnect_ = true;
  bool iocp_pump_ = false;
  bool enforce_compat_ = false;
  bool enforce_compat_patch_attempted_ = false;
  bool enforce_compat_patch_ok_ = false;
  std::string enforce_compat_error_;
  int notify_fallback_pid_ = 0;
  std::wstring notify_fallback_path_;
  std::vector<StepResult> steps_;
  std::vector<std::string> warnings_;
};

// True when the document contains an enforcing (deny/rewrite) rule for an event
// type whose enforcing descriptor is constructible only with the in-memory
// espclient.dll compat patch. A host that cannot enable the patch (the
// ProtectedService IPC host) uses this to refuse the document explicitly
// instead of letting the caller read a no-op install as a working denial.
[[nodiscard]] bool DocumentRequiresEnforceCompat(
    const model::RuleDocument& document);

}  // namespace esptool::esp
