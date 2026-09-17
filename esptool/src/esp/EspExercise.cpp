#include "esp/EspExercise.h"

#include <Windows.h>

#include <array>
#include <cstring>
#include <string>
#include <string_view>

#include "esp/EspStatus.h"
#include "process/SameImage.h"
#include "util/StrHelpers.h"

namespace esptool::esp {
namespace {

constexpr unsigned kIsolatedSweepTimeoutMs = 20000;

struct Scratch {
  Guid guid{};
  int count = 0;
  int type = 0;
  void* handle = nullptr;
  void* handle2 = nullptr;
  std::uint32_t property = 1;
  std::array<std::uint32_t, 4> properties{1, 2, 3, 4};
  std::array<std::uint32_t, kContextKeyDwords> context{};
  std::array<std::uint8_t, 64> blob{};
  wchar_t wide_path[MAX_PATH]{};
  wchar_t wide_name[128]{};
  ClientRegisterDescriptor register_desc{};
  RuleDescriptor rule_desc{};

  Scratch() {
    std::memcpy(wide_name, kDefaultClientNameWide,
                sizeof(kDefaultClientNameWide));
    FillDefaultByPath(wide_path);
  }

  static void FillDefaultByPath(wchar_t* dest) {
    constexpr wchar_t kFallback[] = L"C:\\Windows\\notepad.exe";
    wchar_t directory[MAX_PATH]{};
    const UINT length = GetWindowsDirectoryW(directory, MAX_PATH);
    if (length == 0 || length >= MAX_PATH) {
      wcsncpy_s(dest, MAX_PATH, kFallback, _TRUNCATE);
      return;
    }
    const bool slash =
        directory[length - 1] == L'\\' || directory[length - 1] == L'/';
    if (wcscat_s(directory, slash ? L"notepad.exe" : L"\\notepad.exe") != 0) {
      wcsncpy_s(dest, MAX_PATH, kFallback, _TRUNCATE);
      return;
    }
    wcsncpy_s(dest, MAX_PATH, directory, _TRUNCATE);
  }
};

void NoopQueueNotification(void* notification, void* context) {
  static_cast<void>(notification);
  static_cast<void>(context);
}

[[nodiscard]] bool Contains(std::string_view value,
                            std::string_view needle) noexcept {
  return value.find(needle) != std::string_view::npos;
}

[[nodiscard]] bool IsFilterConstructor(std::string_view name) noexcept {
  return name.starts_with("EspCreate") && Contains(name, "Filter");
}

[[nodiscard]] bool IsQuery(std::string_view name) noexcept {
  return name.starts_with("EspQuery") && Contains(name, "Properties");
}

[[nodiscard]] bool IsSupportProbe(std::string_view name) noexcept {
  return name.starts_with("EspIs") && Contains(name, "PropertySupported");
}

[[nodiscard]] bool IsReference(std::string_view name) noexcept {
  return name.starts_with("EspCreate") && Contains(name, "Reference");
}

[[nodiscard]] bool IsByPathReference(std::string_view name) noexcept {
  return Contains(name, "ByPath");
}

[[nodiscard]] bool IsByIdReference(std::string_view name) noexcept {
  return Contains(name, "ById");
}

[[nodiscard]] bool IsProcessOrThreadReference(std::string_view name) noexcept {
  return Contains(name, "Process") || Contains(name, "Thread");
}

[[nodiscard]] std::uintptr_t Slot(void* pointer) noexcept {
  return reinterpret_cast<std::uintptr_t>(pointer);
}

template <typename Tag>
[[nodiscard]] std::uintptr_t Slot(Opaque<Tag> object) noexcept {
  return Slot(object.abi());
}

using ArgVec = std::array<std::uintptr_t, EspApi::kMaxArity>;

[[nodiscard]] bool FillClientArguments(std::string_view name,
                                       EspSession& session, Scratch& scratch,
                                       ArgVec& arguments) {
  if (name == "EspConnectClient") {
    arguments = {Slot(&scratch.guid), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspDisconnectClient") {
    arguments = {0};
    return true;
  }
  if (name == "EspRegisterClient") {
    scratch.register_desc = {};
    scratch.register_desc.id = session.ClientId();
    scratch.register_desc.name = scratch.wide_name;
    scratch.register_desc.altitude = kDefaultClientAltitudeWide;
    arguments = {Slot(&scratch.register_desc)};
    return true;
  }
  if (name == "EspUnregisterClient") {
    arguments = {Slot(&scratch.guid)};
    return true;
  }
  if (name == "EspRemoveAllRulesForClient") {
    arguments = {Slot(session.ClientHandle())};
    return true;
  }
  if (name == "EspQueryClientDescriptor") {
    arguments = {Slot(&scratch.guid), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspEnumerateConnectedClients" ||
      name == "EspEnumerateRegisteredClients") {
    arguments = {Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillQueueArguments(std::string_view name,
                                      EspSession& session, Scratch& scratch,
                                      ArgVec& arguments) {
  const Client client = session.ClientHandle();
  const Queue queue = session.QueueHandle();
  if (name == "EspConnectEventQueueWithCallback") {
    arguments = {Slot(queue), 0, 0, 0};
    return true;
  }
  if (name == "EspCreateEventQueue") {
    arguments = {Slot(client), 0, Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspOpenEventQueue") {
    arguments = {Slot(client), Slot(&scratch.guid), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspConnectEventQueueWithIocp") {
    arguments = {Slot(queue), 0, Slot(&scratch.handle2)};
    return true;
  }
  if (name == "EspCloseEventQueue") {
    arguments = {0};
    return true;
  }
  if (name == "EspDisconnectEventQueue" ||
      name == "EspRemoveEventQueueStateChangeCallback" ||
      name == "EspClearEventQueue") {
    arguments = {Slot(queue)};
    return true;
  }
  if (name == "EspSetEventQueueStateChangeCallback") {
    arguments = {Slot(queue), 0, 0, 0};
    return true;
  }
  if (name == "EspGetEventQueueId") {
    arguments = {Slot(queue), Slot(&scratch.guid)};
    return true;
  }
  if (name == "EspEnumerateEventQueueIds") {
    arguments = {Slot(client), 0, Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillNotificationArguments(std::string_view name,
                                             EspSession& session,
                                             Scratch& scratch,
                                             ArgVec& arguments) {
  if (name == "EspArmEventNotification") {
    arguments = {Slot(session.QueueHandle()), 0};
    return true;
  }
  if (name == "EspCompleteEventNotification" ||
      name == "EspFreeEventNotification") {
    arguments = {0};
    return true;
  }
  if (name == "EspGetEventCapabilities") {
    arguments = {Slot(session.QueueHandle()), 0, Slot(&scratch.count)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillCloseArguments(std::string_view name,
                                      ArgVec& arguments) {
  if (name == "EspCloseFilter" || name == "EspCloseRule" ||
      name == "EspCloseCollection" || name == "EspCloseEventObjectReference") {
    arguments = {0};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillFilterArguments(std::string_view name, Scratch& scratch,
                                       ArgVec& arguments) {
  if (name == "EspCreateNotFilter") {
    arguments = {0, Slot(&scratch.handle2)};
    return true;
  }
  if (name == "EspCreateAndFilter" || name == "EspCreateOrFilter" ||
      name == "EspCreateXorFilter") {
    arguments = {0, 0, Slot(&scratch.handle)};
    return true;
  }
  if (IsFilterConstructor(name)) {
    if (name == "EspCreateFilter") {
      arguments = {1, 0, Slot(&scratch.handle)};
    } else {
      arguments = {1, 1, 0, Slot(&scratch.handle)};
    }
    return true;
  }
  return false;
}

[[nodiscard]] bool FillRuleArguments(std::string_view name, EspSession& session,
                                     Scratch& scratch, ArgVec& arguments) {
  const Client client = session.ClientHandle();
  if (name == "EspCreateRule") {
    scratch.rule_desc = {};
    arguments = {Slot(&scratch.rule_desc), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspUpdateRules") {
    arguments = {Slot(client), 0, 0, 0};
    return true;
  }
  if (name == "EspEnumerateRuleIds") {
    arguments = {Slot(client), 0, Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspEnumerateAllRulesForClient") {
    arguments = {Slot(client), Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspGetRuleId") {
    arguments = {Slot(client), Slot(&scratch.guid)};
    return true;
  }
  if (name == "EspRemoveRulesForClient") {
    arguments = {Slot(client), 0};
    return true;
  }
  return false;
}

void FillByPathReference(const ExportDescriptor& descriptor, Client client,
                         Scratch& scratch, ArgVec& arguments) {
  arguments = descriptor.arity >= 4
                  ? ArgVec{Slot(client), Slot(scratch.wide_path), 0,
                           Slot(&scratch.handle)}
                  : ArgVec{Slot(client), Slot(scratch.wide_path),
                           Slot(&scratch.handle), 0};
}

void FillByIdReference(const ExportDescriptor& descriptor, Client client,
                       Scratch& scratch, ArgVec& arguments) {
  arguments = descriptor.arity >= 4
                  ? ArgVec{Slot(client), Slot(scratch.blob.data()), 0,
                           Slot(&scratch.handle)}
                  : ArgVec{Slot(client), Slot(scratch.blob.data()),
                           Slot(&scratch.handle), 0};
}

[[nodiscard]] bool FillReferenceArguments(const ExportDescriptor& descriptor,
                                          EspSession& session, Scratch& scratch,
                                          ArgVec& arguments) {
  const std::string_view name = descriptor.name;
  const Client client = session.ClientHandle();
  if (name == "EspDuplicateEventObjectReference" ||
      name == "EspGetEventObjectFromReference") {
    arguments = {0, Slot(&scratch.handle2)};
    return true;
  }
  if (name == "EspGetEventObjectId") {
    arguments = {0, Slot(&scratch.guid)};
    return true;
  }
  if (name == "EspGetEventObjectType") {
    arguments = {0, Slot(&scratch.type)};
    return true;
  }
  if (!IsReference(name)) {
    return false;
  }
  if (IsByPathReference(name)) {
    FillByPathReference(descriptor, client, scratch, arguments);
    return true;
  }
  if (IsByIdReference(name)) {
    FillByIdReference(descriptor, client, scratch, arguments);
    return true;
  }
  if (IsProcessOrThreadReference(name)) {
    arguments = {Slot(client),
                 static_cast<std::uintptr_t>(GetCurrentProcessId()),
                 Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspCreateEventObjectReference") {
    arguments = {0, Slot(&scratch.handle2)};
    return true;
  }
  arguments = {Slot(client), Slot(scratch.wide_path), Slot(&scratch.handle)};
  return true;
}

[[nodiscard]] bool FillQueryArguments(std::string_view name,
                                      EspSession& session, Scratch& scratch,
                                      ArgVec& arguments) {
  if (IsQuery(name)) {
    arguments = {Slot(session.ClientHandle()), 1,
                 Slot(scratch.properties.data()), Slot(&scratch.handle2)};
    return true;
  }
  if (IsSupportProbe(name)) {
    arguments = {Slot(session.ClientHandle()), scratch.property,
                 Slot(&scratch.count)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillCollectionArguments(std::string_view name,
                                           EspSession& session,
                                           Scratch& scratch,
                                           ArgVec& arguments) {
  const Client client = session.ClientHandle();
  if (name == "EspCreateCollection") {
    arguments = {Slot(client), 0, Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspOpenCollection") {
    arguments = {Slot(client), Slot(&scratch.guid), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspUpdateCollection") {
    arguments = {0, 0, 0, 0};
    return true;
  }
  if (name == "EspEnumerateCollectionEntries") {
    arguments = {0, Slot(&scratch.count), Slot(&scratch.handle2)};
    return true;
  }
  if (name == "EspEnumerateCollectionIds") {
    arguments = {Slot(client), 0, Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspGetCollectionId") {
    arguments = {0, Slot(&scratch.guid)};
    return true;
  }
  if (name == "EspGetCollectionType") {
    arguments = {0, Slot(&scratch.type)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillContextArguments(std::string_view name,
                                        EspSession& session, Scratch& scratch,
                                        ArgVec& arguments) {
  const Client client = session.ClientHandle();
  if (name == "EspSetClientContextKey") {
    arguments = {Slot(client), Slot(scratch.context.data())};
    return true;
  }
  if (name == "EspSetEventObjectContextKey") {
    arguments = {0, Slot(scratch.context.data())};
    return true;
  }
  if (name == "EspEnumerateAllClientContextKeys") {
    arguments = {Slot(client), Slot(&scratch.count), Slot(&scratch.handle)};
    return true;
  }
  if (name == "EspEnumerateAllEventObjectContextKeys") {
    arguments = {0, Slot(&scratch.count), Slot(&scratch.handle2)};
    return true;
  }
  return false;
}

[[nodiscard]] bool FillUtilityArguments(std::string_view name, Scratch& scratch,
                                        ArgVec& arguments) {
  if (name == "EspInitUnicodeString") {
    arguments = {Slot(&scratch.handle), Slot(scratch.wide_name)};
    return true;
  }
  if (name == "EspStringMatchesPattern") {
    arguments = {Slot(scratch.wide_path), Slot(scratch.wide_name),
                 Slot(&scratch.count)};
    return true;
  }
  if (name == "EspFreeMemory") {
    arguments = {0};
    return true;
  }
  return false;
}

void BuildArguments(const ExportDescriptor& descriptor, EspSession& session,
                    Scratch& scratch, ArgVec& arguments) {
  arguments.fill(0);
  scratch.guid = session.ClientId();
  scratch.count = 0;
  scratch.handle = nullptr;
  scratch.handle2 = nullptr;
  const std::string_view name = descriptor.name;
  if (FillClientArguments(name, session, scratch, arguments) ||
      FillQueueArguments(name, session, scratch, arguments) ||
      FillNotificationArguments(name, session, scratch, arguments) ||
      FillCloseArguments(name, arguments) ||
      FillFilterArguments(name, scratch, arguments) ||
      FillRuleArguments(name, session, scratch, arguments) ||
      FillReferenceArguments(descriptor, session, scratch, arguments) ||
      FillQueryArguments(name, session, scratch, arguments) ||
      FillCollectionArguments(name, session, scratch, arguments) ||
      FillContextArguments(name, session, scratch, arguments) ||
      FillUtilityArguments(name, scratch, arguments)) {
    return;
  }
}

[[nodiscard]] bool SeedOutcome(const ExportDescriptor& descriptor,
                               ExportOutcome& outcome) {
  outcome.name = descriptor.name;
  outcome.arity = descriptor.arity;
  outcome.resolved = descriptor.address != nullptr;
  if (EspExercise::IsExcluded(descriptor.name)) {
    outcome.detail = "excluded from CallRaw";
    return false;
  }
  if (!outcome.resolved) {
    outcome.detail = "not exported by the loaded library";
    return false;
  }
  return true;
}

}  // namespace

bool EspExercise::IsExcluded(std::string_view name) {
  return name == "_DllMainCRTStartup" ||
         name == "EspCreateFileStreamReferenceById";
}

void EspExercise::PrepareSession() {
  if (!session_.ClientHandle()) {
    return;
  }
  if (!session_.QueueHandle()) {
    (void)session_.CreateQueue();
  }
  if (session_.QueueHandle()) {
    (void)session_.ConnectQueueToCallback(&NoopQueueNotification, nullptr);
  }
}

std::vector<ExportOutcome> EspExercise::RunInProcess() {
  PrepareSession();
  Scratch scratch;
  std::vector<ExportOutcome> outcomes;
  outcomes.reserve(api_.ExportCount());
  for (const ExportDescriptor& descriptor : api_.Exports()) {
    ExportOutcome outcome;
    if (!SeedOutcome(descriptor, outcome)) {
      outcomes.push_back(std::move(outcome));
      continue;
    }
    if (descriptor.name == "EspAllocateEventNotification") {
      outcome.detail = "skipped: unarmed Allocate AVs in Free/teardown";
      outcomes.push_back(std::move(outcome));
      continue;
    }
    ArgVec arguments{};
    BuildArguments(descriptor, session_, scratch, arguments);
    outcome.invoked = true;
    outcome.result = session_.CallRaw(descriptor, arguments);
    outcome.detail = DescribeResult(static_cast<EspResult>(outcome.result));
    outcomes.push_back(std::move(outcome));
  }
  return outcomes;
}

std::vector<ExportOutcome> EspExercise::RunIsolated() {
  std::vector<ExportOutcome> outcomes;
  outcomes.reserve(api_.ExportCount());
  const std::wstring host_library = api_.LoadedPath();
  for (const ExportDescriptor& descriptor : api_.Exports()) {
    ExportOutcome outcome;
    if (!SeedOutcome(descriptor, outcome)) {
      outcomes.push_back(std::move(outcome));
      continue;
    }
    std::vector<std::wstring> arguments;
    arguments.emplace_back(L"--worker");
    if (!host_library.empty()) {
      arguments.emplace_back(L"--dll");
      arguments.push_back(host_library);
    }
    arguments.emplace_back(L"call-one");
    arguments.push_back(text::ToUtf16(descriptor.name));

    process::LaunchOptions launch;
    launch.hidden = true;
    launch.wait_ms = kIsolatedSweepTimeoutMs;
    launch.terminate_on_timeout = true;
    launch.timeout_exit_code = static_cast<std::uint32_t>(kStatusCancelled);
    const process::LaunchOutcome launched =
        process::RunSameImage(arguments, launch);
    if (!launched.created) {
      outcome.detail = launched.error.empty() ? "child process creation failed"
                                              : launched.error;
      outcomes.push_back(std::move(outcome));
      continue;
    }
    const std::uint32_t exit_code = launched.exit_code;
    outcome.invoked = true;
    outcome.result =
        static_cast<std::int64_t>(static_cast<std::int32_t>(exit_code));
    outcome.detail = DescribeResult(static_cast<EspResult>(exit_code));
    if (exit_code == static_cast<std::uint32_t>(kStatusAccessViolation)) {
      outcome.detail = "access violation";
    } else if (exit_code ==
               static_cast<std::uint32_t>(kStatusStackBufferOverrun)) {
      outcome.detail = "stack buffer overrun";
    } else if (exit_code == static_cast<std::uint32_t>(kStatusCancelled)) {
      outcome.detail = "timed out and was terminated";
    }
    outcomes.push_back(std::move(outcome));
  }
  return outcomes;
}

std::int64_t EspExercise::CallOne(const EspApi& api, EspSession& session,
                                  std::string_view name) {
  if (IsExcluded(name)) {
    return static_cast<std::int64_t>(kInvalidArg);
  }
  const ExportDescriptor* descriptor = api.Find(name);
  if (descriptor == nullptr || descriptor->address == nullptr) {
    return static_cast<std::int64_t>(kModNotFound);
  }
  Scratch scratch;
  ArgVec arguments{};
  BuildArguments(*descriptor, session, scratch, arguments);
  return api.Invoke(*descriptor, arguments);
}

}  // namespace esptool::esp
