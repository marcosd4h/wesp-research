// Command bodies and Dispatch. CommandNeedsWorker hops to a same-image
// SYSTEM+TCB child and returns that child's exit code. The parent must
// not fall through into DispatchLocal/DispatchEsp after a hop. token
// set/clear stay in this process and only call RequireSystemWithTcb.

#include "cli/Commands.h"

#include <Windows.h>

#include <algorithm>
#include <array>
#include <bit>
#include <chrono>
#include <cstddef>
#include <cstdint>
#include <cstdio>
#include <format>
#include <fstream>
#include <iterator>
#include <limits>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

#include "cli/Options.h"
#include "esp/EspApi.h"
#include "esp/EspEnforceCompat.h"
#include "esp/EspEventIds.h"
#include "esp/EspExercise.h"
#include "esp/EspFilterAbi.h"
#include "esp/EspNtPath.h"
#include "esp/EspRefAbi.h"
#include "esp/EspRuleAbi.h"
#include "esp/EspSession.h"
#include "esp/EspStatus.h"
#include "ipc/PipeChannel.h"
#include "model/RuleDocument.h"
#include "model/RuleParser.h"
#include "ppl/ProtectedService.h"
#include "ppl/Protection.h"
#include "ppl/TokenAttribute.h"
#include "process/SameImage.h"
#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool::cli {
namespace {

constexpr unsigned kUniqueAltitudeBase = 450000;
constexpr unsigned kUniqueAltitudeSpan = 40000;
constexpr int kLifetimeFfiMin = 1;
constexpr int kLifetimeFfiMax = 4;

void PrintSeparator() {
  std::printf("------------------------------------------------------------\n");
}

[[nodiscard]] int Fail(const std::string& message) {
  std::fprintf(stderr, "%s\n", message.c_str());
  return 1;
}

[[nodiscard]] int RequireTcbOrFail() {
  std::string error;
  if (!ppl::RequireSystemWithTcb(error)) {
    return Fail(error);
  }
  return 0;
}

[[nodiscard]] model::ClientSpec UniqueClientSpec(std::string_view prefix) {
  model::ClientSpec spec;
  const unsigned stamp = static_cast<unsigned>(GetTickCount64() & 0xFFFFFFFFu) ^
                         static_cast<unsigned>(GetCurrentProcessId());
  spec.name = std::format("{}-{:08x}", prefix, stamp);
  spec.altitude =
      std::to_string(kUniqueAltitudeBase + (stamp % kUniqueAltitudeSpan));
  return spec;
}

void PrintTrustState() {
  const ppl::SecureBootState secure_boot = ppl::QuerySecureBootEnabled();
  ppl::TokenAttributeState attribute;
  std::string attribute_error;
  const bool have_attribute =
      ppl::QueryWespPermission(attribute, attribute_error);

  const ppl::PrivilegeState tcb = ppl::QueryPrivilege(SE_TCB_NAME);
  std::printf("account: %s\n",
              ppl::IsSystemAccount() ? "SYSTEM" : "not-SYSTEM");
  std::printf("elevated: %s\n", ppl::IsElevated() ? "yes" : "no");
  std::printf("tcb: %s\n",
              tcb.present ? (tcb.enabled ? "enabled" : "present") : "absent");
  std::printf("protection: %s\n",
              ppl::QueryCurrentProcess().Describe().c_str());
  std::printf("attribute: %s\n", attribute.Describe().c_str());
  if ((!have_attribute || !attribute.present) && !attribute_error.empty()) {
    std::printf("attribute-error: %s\n", attribute_error.c_str());
  }
  std::printf("codeintegrity: %s\n",
              ppl::QueryCodeIntegrity().Describe().c_str());
  if (secure_boot.queried) {
    std::printf("secureboot: %s\n", secure_boot.enabled ? "on" : "off");
  } else {
    std::printf("secureboot: unknown (%s)\n", secure_boot.error.c_str());
  }
}

[[nodiscard]] bool CommandNeedsSystemContext(const Options& options) {
  return options.command == "token" && !options.positional.empty() &&
         options.positional[0] != "status";
}

[[nodiscard]] ProvisioningContext ProbeCurrentTrustContext() {
  ProvisioningContext ctx;
  ctx.is_system = ppl::IsSystemAccount();
  const auto tcb = ppl::QueryPrivilege(SE_TCB_NAME);
  ctx.is_tcb = tcb.present && tcb.enabled;

  const auto prot = ppl::QueryCurrentProcess();
  if (!prot.queried || prot.query_status < 0) {
    ctx.probe_ok = false;
    ctx.error =
        std::format("failed to query process protection: status 0x{:08X}",
                    static_cast<std::uint32_t>(prot.query_status));
    return ctx;
  }
  ctx.is_ppl = prot.IsAntimalwareLight();

  const auto ci = ppl::QueryCodeIntegrity();
  if (!ci.queried || ci.query_status < 0) {
    ctx.probe_ok = false;
    ctx.error =
        std::format("failed to query code integrity policy: status 0x{:08X}",
                    static_cast<std::uint32_t>(ci.query_status));
    return ctx;
  }
  ctx.test_signing = ci.TestSigning();

  ppl::TokenAttributeState attr;
  std::string attr_err;
  if (!ppl::QueryWespPermission(attr, attr_err)) {
    ctx.probe_ok = false;
    ctx.error = std::format(
        "failed to query primary token security attributes: {}", attr_err);
    return ctx;
  }
  ctx.attribute_present = attr.present;
  ctx.attribute_permission = attr.permission;
  ctx.probe_ok = true;
  return ctx;
}

[[nodiscard]] int HopToWorker(const Options& options) {
  if (const int status = RequireTcbOrFail(); status != 0) {
    return status;
  }
  Log::Info("parent: SYSTEM+TCB verified, launching worker");
  const process::LaunchOutcome launched = process::LaunchWorker(options);
  if (!launched.created) {
    if (Log::WouldLog(LogLevel::Error)) {
      Log::Error(
          std::format("parent: worker launch failed: {}", launched.error));
    }
    return Fail(launched.error);
  }
  if (Log::WouldLog(LogLevel::Info)) {
    Log::Info(std::format("parent: worker exited {}", launched.exit_code));
  }
  return static_cast<int>(launched.exit_code);
}

[[nodiscard]] int PrepareThisProcess(const Options& options,
                                     const TrustPlan& plan) {
  if (const int status = RequireTcbOrFail(); status != 0) {
    return status;
  }
  if (plan.clean_needed || options.clear_attribute) {
    std::string delete_error;
    if (!ppl::DeleteWespPermission(delete_error)) {
      return Fail(std::format("could not clear {}: {}",
                              ppl::kWespPermissionClaim, delete_error));
    }
    if (Log::WouldLog(LogLevel::Info)) {
      Log::Info(std::format(
          "worker: pre-existing {} attribute cleared for test-signing "
          "compatibility",
          ppl::kWespPermissionClaim));
    }
  } else if (plan.stamp_needed) {
    std::string error;
    if (!ppl::SetWespPermission(plan.target_permission, error)) {
      return Fail(std::format("could not set {}: {}", ppl::kWespPermissionClaim,
                              error));
    }
    if (Log::WouldLog(LogLevel::Info)) {
      Log::Info(std::format("worker: {} set to {}", ppl::kWespPermissionClaim,
                            plan.target_permission));
    }
  }
  return 0;
}

void PrintSteps(const esp::EspSession& session) {
  for (const esp::StepResult& step : session.Steps()) {
    std::printf("%-4s %-40s %-10s %s\n", step.ok ? "ok" : "fail",
                step.step.c_str(), esp::HexResult(step.result).c_str(),
                esp::DescribeResult(step.result).c_str());
  }
}

void PrintWarnings(const esp::EspSession& session) {
  for (const std::string& warning : session.Warnings()) {
    std::printf("warning: %s\n", warning.c_str());
    Log::Warn(warning);
  }
}

void LogSteps(const esp::EspSession& session) {
  if (!Log::WouldLog(LogLevel::Info)) {
    return;
  }
  for (const esp::StepResult& step : session.Steps()) {
    Log::Info(std::format("{} {} {} {}", step.ok ? "ok" : "fail", step.step,
                          esp::HexResult(step.result),
                          esp::DescribeResult(step.result)));
  }
}

void ReportSession(const esp::EspSession& session, bool log_steps) {
  PrintSteps(session);
  if (log_steps) {
    LogSteps(session);
  }
  PrintWarnings(session);
}

// NTSTATUS exception codes arrive as negative results in the isolated sweep.
[[nodiscard]] bool IsFault(std::int64_t result) noexcept {
  const std::uint32_t raw = static_cast<std::uint32_t>(result);
  return (raw & esp::kNtStatusErrorMask) == esp::kNtStatusErrorMask;
}

[[nodiscard]] int RunExports(const esp::EspApi& api) {
  PrintSeparator();
  std::printf("%-44s %-6s %s\n", "export", "arity", "resolved");
  for (const esp::ExportDescriptor& descriptor : api.Exports()) {
    std::printf("%-44s %-6u %s\n", descriptor.name.c_str(),
                static_cast<unsigned>(descriptor.arity),
                descriptor.address != nullptr ? "yes" : "no");
  }
  PrintSeparator();
  std::printf("resolved %zu of %zu\n", api.ResolvedCount(), api.ExportCount());
  const std::vector<std::string> missing = api.Missing();
  std::printf("missing %zu:", missing.size());
  for (const std::string& name : missing) {
    std::printf(" %s", name.c_str());
  }
  std::printf("\n");
  return 0;
}

[[nodiscard]] int RunStatus(const esp::EspApi& api) {
  std::printf("dll: %s\n", text::ToUtf8(api.LoadedPath()).c_str());
  std::printf("resolved %zu of %zu\n", api.ResolvedCount(), api.ExportCount());
  PrintTrustState();
  return 0;
}

[[nodiscard]] int RunConnect(const esp::EspApi& api) {
  PrintTrustState();
  PrintSeparator();
  esp::EspSession session(api);
  const model::ClientSpec client;
  const bool connected = session.Connect(client);
  (void)session.CreateQueue();
  (void)session.ArmNotification();
  ReportSession(session, false);
  session.Disconnect();
  return connected ? 0 : 1;
}

enum class RulesPrep {
  FailedConnect,
  FailedQueue,
  FailedRemoveRules,
  FailedInstall,
  Partial,
  Ok,
};

// Cleans disconnected client identities from prior crashed or orphaned sessions
// so rule loading starts from a clean baseline. When release_persistent is false,
// connects to each candidate client to inspect persistent rule count; if > 0, the
// intentional persist client is preserved. When release_persistent is true
// (e.g. via --fresh), all disconnected clients and persistent rules are released.
// Connected/active clients (e.g. Defender with open port) return ERROR_INVALID_STATE
// (0x8007139F) and are untouched.
unsigned CleanOrphanClients(const esp::EspApi& api, bool release_persistent,
                            std::string_view command) {
  esp::EspSession probe(api);
  int count = 0;
  std::vector<esp::Guid> ids;
  if (!probe.EnumerateClients(count, &ids) || ids.empty()) {
    return 0;
  }
  unsigned cleared = 0;
  for (const esp::Guid& id : ids) {
    if (!release_persistent) {
      // Connect without registering to probe persistent rule count.
      esp::EspSession checker(api);
      if (checker.ConnectExisting(id)) {
        int persist_count = 0;
        const bool enum_ok = checker.EnumerateRuleIds(
            static_cast<int>(esp::kLifetimePersistFfi), persist_count);
        checker.Disconnect();
        // Fail-closed preserve: if probe succeeded and has persistent rules,
        // or if probe failed, preserve the client.
        if (!enum_ok || persist_count > 0) {
          continue;
        }
      } else {
        // Could not connect to inspect; fail-closed preserve.
        continue;
      }
    }
    // Probe session disconnected; target rests in state 2 (disconnected).
    if (probe.UnregisterClientId(id)) {
      ++cleared;
    }
  }
  if (cleared > 0 && Log::WouldLog(LogLevel::Info)) {
    Log::Info(std::format(
        "{}: released {} leftover disconnected client(s) on start", command,
        cleared));
  }
  return cleared;
}

[[nodiscard]] bool DocumentNeedsQueue(
    const model::RuleDocument& document) noexcept {
  return std::ranges::any_of(document.rules, [](const model::RuleSpec& spec) {
    return esp::ResolvedActionNeedsQueue(spec.action, spec.actionName,
                                         spec.selector_override);
  });
}

[[nodiscard]] RulesPrep PrepareRulesSession(esp::EspSession& session,
                                            const model::RuleDocument& document,
                                            const Options& options) {
  if (!session.Connect(document.client)) {
    return RulesPrep::FailedConnect;
  }
  session.SetEnforceCompat(options.enforce_compat);
  if (options.bypass_eventtype) {
    std::string bypass_error;
    if (!esp::ApplyEventTypeBypassPatch(&bypass_error)) {
      Log::Error(std::format("event-type bypass failed: {}", bypass_error));
      return RulesPrep::FailedInstall;
    }
  }
  // Persist/deny/rewrite must not create a session queue. Persist store
  // walks client queues and rejects a live UM queue pointer (E_INVALIDARG).
  if (DocumentNeedsQueue(document) && !session.CreateQueue()) {
    return RulesPrep::FailedQueue;
  }
  // Fail-closed release of any prior rules on this client so rule loading is always fresh.
  if (!session.RemoveAllRules()) {
    Log::Error("rules: EspRemoveAllRulesForClient failed on start");
    return RulesPrep::FailedRemoveRules;
  }
  const esp::InstallStatus status = session.InstallRules(document);
  if (status == esp::InstallStatus::Failed) {
    return RulesPrep::FailedInstall;
  }
  if (status == esp::InstallStatus::Partial) {
    return RulesPrep::Partial;
  }
  return RulesPrep::Ok;
}

[[nodiscard]] std::optional<model::ParseOutcome> LoadRuleDocument(
    const Options& options, std::string_view command) {
  if (options.rules_path.empty()) {
    std::fprintf(stderr, "%s\n",
                 std::format("{} requires --rules <path>", command).c_str());
    return std::nullopt;
  }
  return model::ParseRuleFile(options.rules_path);
}

[[nodiscard]] int RunRules(const esp::EspApi& api, const Options& options) {
  const auto parsed = LoadRuleDocument(options, "rules");
  if (!parsed) {
    return 1;
  }
  if (!parsed->ok) {
    return Fail(std::format("rule parse error: {}", parsed->error));
  }
  (void)CleanOrphanClients(api, options.fresh, "rules");
  esp::EspSession session(api);
  const RulesPrep prep =
      PrepareRulesSession(session, parsed->document, options);
  if (prep == RulesPrep::FailedRemoveRules) {
    ReportSession(session, false);
    session.Disconnect();
    return 1;
  }
  const bool installed = prep == RulesPrep::Ok;
  if (prep == RulesPrep::Partial) {
    // Some rules were committed and at least one was refused. A zero exit code
    // would read as "the whole document is armed", so keep it non-zero.
    Log::Error(
        "rules: partial install; the committed rules are active but at least "
        "one rule was refused");
  }
  ReportSession(session, false);
  // Deny/cancel have no queue. --duration keeps the session alive so a
  // matching trigger can hit an in-path action before Disconnect.
  if (installed && options.duration_set && options.duration_ms > 0) {
    std::printf("rules-hold %u\n", options.duration_ms);
    const ULONGLONG start_tick = GetTickCount64();
    if (DocumentNeedsQueue(parsed->document)) {
      Log::Info("rules: rules installed, pumping notifications");
      // For rules --duration, unless the user explicitly passed --max, pump
      // continuously for duration_ms without capping at the monitor default (10).
      const unsigned max_events =
          options.max_notifications_set ? options.max_notifications
                                        : std::numeric_limits<unsigned>::max();
      if (options.iocp) {
        session.PumpNotificationsIocp(options.duration_ms, max_events);
      } else {
        session.PumpNotifications(options.duration_ms, max_events);
      }
      Log::Info(std::format("rules: received {} notifications",
                            session.NotificationsReceived()));
      // If max_notifications capped the pump early, sleep any remaining
      // duration so mixed in-path deny/cancel rules are never dropped prematurely.
      const ULONGLONG elapsed = GetTickCount64() - start_tick;
      if (elapsed < options.duration_ms) {
        std::this_thread::sleep_for(
            std::chrono::milliseconds{options.duration_ms - elapsed});
      }
    } else {
      Log::Info(
          "rules: holding session (in-path rules active, no user-mode queue)");
      std::this_thread::sleep_for(
          std::chrono::milliseconds{options.duration_ms});
    }
    Log::Info("rules: hold complete");
  }
  session.Disconnect();
  Log::Info("rules: session disconnected");
  return installed ? 0 : 1;
}

[[nodiscard]] int RunMonitor(const esp::EspApi& api, const Options& options) {
  const auto parsed = LoadRuleDocument(options, "monitor");
  if (!parsed) {
    return 1;
  }
  if (!parsed->ok) {
    const std::string message =
        std::format("rule parse error: {}", parsed->error);
    Log::Error(message);
    return Fail(message);
  }
  if (Log::WouldLog(LogLevel::Info)) {
    Log::Info(std::format("monitor: parsed {} rules from {}",
                          parsed->document.rules.size(), options.rules_path));
  }
  (void)CleanOrphanClients(api, options.fresh, "monitor");
  esp::EspSession session(api);
  const RulesPrep prep =
      PrepareRulesSession(session, parsed->document, options);
  if (prep != RulesPrep::Ok) {
    if (prep == RulesPrep::FailedConnect) {
      Log::Error("monitor: EspConnectClient failed");
    } else if (prep == RulesPrep::FailedQueue) {
      Log::Error("monitor: EspCreateEventQueue failed");
    } else if (prep == RulesPrep::FailedRemoveRules) {
      Log::Error("monitor: EspRemoveAllRulesForClient failed on start");
    } else if (prep == RulesPrep::Partial) {
      Log::Error(
          "monitor: partial install; at least one rule was refused, so the "
          "monitor is not armed for the whole document");
    } else {
      Log::Error("monitor: InstallRules failed");
    }
    ReportSession(session, true);
    session.Disconnect();
    return 1;
  }
  Log::Info("monitor: rules installed, pumping");
  if (options.iocp) {
    session.PumpNotificationsIocp(options.duration_ms,
                                  options.max_notifications);
  } else {
    session.PumpNotifications(options.duration_ms, options.max_notifications);
  }
  ReportSession(session, true);
  std::printf("received %u notifications\n", session.NotificationsReceived());
  if (Log::WouldLog(LogLevel::Info)) {
    Log::Info(
        std::format("monitor: received {}", session.NotificationsReceived()));
  }
  session.Disconnect();
  Log::Info("monitor: session disconnected");
  // 0 means at least one notification arrived. A clean install with zero events
  // is exit 1.
  return session.NotificationsReceived() > 0 ? 0 : 1;
}

// query/collections/context/exercise always return 0, including after a failed
// Connect.
template <typename Action>
[[nodiscard]] int RunConnectedAction(const esp::EspApi& api, Action action) {
  esp::EspSession session(api);
  (void)session.Connect(model::ClientSpec{});
  action(session);
  ReportSession(session, false);
  session.Disconnect();
  return 0;
}

[[nodiscard]] int RunClients(const esp::EspApi& api) {
  esp::EspSession session(api);
  int count = 0;
  std::vector<esp::Guid> ids;
  const bool ok = session.EnumerateClients(count, &ids);
  std::printf("registered-clients %d\n", count);
  for (const esp::Guid& id : ids) {
    const auto bytes = std::bit_cast<std::array<std::uint8_t, 16>>(id);
    std::printf("client %s\n", text::FormatGuid(bytes).c_str());
  }
  ReportSession(session, false);
  session.Disconnect();
  return ok ? 0 : 1;
}

[[nodiscard]] int RunUnregister(const esp::EspApi& api,
                                const Options& options) {
  if (options.all) {
    esp::EspSession session(api);
    int count = 0;
    std::vector<esp::Guid> ids;
    if (!session.EnumerateClients(count, &ids)) {
      ReportSession(session, false);
      session.Disconnect();
      return 1;
    }
    int cleared = 0;
    for (const esp::Guid& id : ids) {
      if (session.UnregisterClientId(id)) {
        ++cleared;
      }
    }
    std::printf("unregistered %d\n", cleared);
    ReportSession(session, false);
    session.Disconnect();
    return cleared == static_cast<int>(ids.size()) ? 0 : 1;
  }
  if (options.guid.empty()) {
    std::fprintf(stderr, "unregister requires --guid or --all\n");
    return 2;
  }
  std::array<std::uint8_t, 16> bytes{};
  if (!text::ParseGuid(options.guid, bytes)) {
    std::fprintf(stderr, "unregister --guid is not a valid GUID\n");
    return 2;
  }
  const esp::Guid id = std::bit_cast<esp::Guid>(bytes);
  esp::EspSession session(api);
  const bool ok = session.UnregisterClientId(id);
  ReportSession(session, false);
  session.Disconnect();
  return ok ? 0 : 1;
}

[[nodiscard]] int RunEnumRules(const esp::EspApi& api) {
  return RunConnectedAction(api, [](esp::EspSession& session) {
    int count = 0;
    (void)session.EnumerateAllRules(count);
    std::printf("rules %d\n", count);
    for (int lifetime = kLifetimeFfiMin; lifetime <= kLifetimeFfiMax;
         ++lifetime) {
      count = 0;
      (void)session.EnumerateRuleIds(lifetime, count);
      std::printf("rules-lifetime-%d %d\n", lifetime, count);
    }
  });
}

[[nodiscard]] int RunRemoveRules(const esp::EspApi& api) {
  return RunConnectedAction(
      api, [](esp::EspSession& session) { (void)session.RemoveAllRules(); });
}

[[nodiscard]] int RunPersistRules(const esp::EspApi& api,
                                  const Options& options) {
  const auto parsed = LoadRuleDocument(options, "persist-rules");
  if (!parsed) {
    return 1;
  }
  if (!parsed->ok) {
    return Fail(std::format("rule parse error: {}", parsed->error));
  }
  (void)CleanOrphanClients(api, options.fresh, "persist-rules");
  model::RuleDocument document = parsed->document;
  for (model::RuleSpec& spec : document.rules) {
    spec.lifetime = model::RuleLifetime::Persistent;
  }
  esp::EspSession session(api);
  session.SetUnregisterOnDisconnect(false);
  const RulesPrep prep = PrepareRulesSession(session, document, options);
  int count = 0;
  const bool listed = prep == RulesPrep::Ok &&
                      session.EnumerateRuleIds(
                          static_cast<int>(esp::kLifetimePersistFfi), count);
  std::printf("persist-rules %d\n", count);
  if (!listed || count < 1) {
    session.SetUnregisterOnDisconnect(true);
  }
  ReportSession(session, false);
  session.Disconnect();
  return (listed && count >= 1) ? 0 : 1;
}

[[nodiscard]] int RunOpenQueue(const esp::EspApi& api) {
  // CloseQueue destroys the kernel object. Open by GUID needs the
  // creator queue to stay alive. Plan: second session, same GUID.
  esp::EspSession owner(api);
  if (!owner.Connect(UniqueClientSpec("esptool-oq1")) || !owner.CreateQueue()) {
    ReportSession(owner, false);
    owner.Disconnect();
    return 1;
  }
  esp::Guid id{};
  if (!owner.GetQueueId(id)) {
    ReportSession(owner, false);
    owner.Disconnect();
    return 1;
  }
  esp::EspSession opener(api);
  const bool second_session = opener.Connect(UniqueClientSpec("esptool-oq2")) &&
                              opener.OpenQueueById(id);
  bool opened = second_session;
  if (!opened) {
    opened = owner.OpenQueueById(id);
  }
  std::printf("open-queue %s\n", opened ? "ok" : "fail");
  ReportSession(owner, false);
  ReportSession(opener, false);
  opener.Disconnect();
  owner.Disconnect();
  return opened ? 0 : 1;
}

[[nodiscard]] int RunTrust(const esp::EspApi& api) {
  PrintTrustState();
  PrintSeparator();
  esp::EspSession session(api);
  const bool connected = session.Connect(UniqueClientSpec("esptool-trust"));
  (void)session.CreateQueue();
  ReportSession(session, false);
  session.Disconnect();
  return connected ? 0 : 1;
}

[[nodiscard]] bool ParseCsvIds(std::string_view text,
                               std::vector<unsigned>& out) {
  out.clear();
  if (text.empty()) {
    return true;
  }
  for (const std::string& part : text::Split(std::string(text), ',')) {
    const std::string_view trimmed = text::Trim(part);
    std::uint64_t parsed = 0;
    if (!text::ParseUnsigned(trimmed, parsed) ||
        parsed > std::numeric_limits<unsigned>::max()) {
      return false;
    }
    out.push_back(static_cast<unsigned>(parsed));
  }
  return true;
}

[[nodiscard]] int ResolvePid(std::string_view text) {
  if (text.empty() || text::EqualsIgnoreCase(text, "self")) {
    return static_cast<int>(GetCurrentProcessId());
  }
  std::uint64_t parsed = 0;
  if (!text::ParseUnsigned(text, parsed) ||
      parsed > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
    return -1;
  }
  return static_cast<int>(parsed);
}

[[nodiscard]] int ResolveTid(std::string_view text) {
  if (text.empty() || text::EqualsIgnoreCase(text, "self")) {
    return static_cast<int>(GetCurrentThreadId());
  }
  std::uint64_t parsed = 0;
  if (!text::ParseUnsigned(text, parsed) ||
      parsed > static_cast<std::uint64_t>(std::numeric_limits<int>::max())) {
    return -1;
  }
  return static_cast<int>(parsed);
}

[[nodiscard]] bool ParseGuidOption(std::string_view text, esp::Guid& out) {
  std::array<std::uint8_t, text::kGuidOctets> bytes{};
  if (!text::ParseGuid(text, bytes)) {
    return false;
  }
  out = std::bit_cast<esp::Guid>(bytes);
  return true;
}

[[nodiscard]] bool ParseFileIdHex(std::string_view text,
                                  esp::FileIdDescriptorRaw& out) {
  std::string hex;
  for (const char ch : text) {
    if (ch == '-' || ch == ' ' || ch == ':') {
      continue;
    }
    hex.push_back(ch);
  }
  if (hex.size() != 32) {
    return false;
  }
  out = esp::FileIdDescriptorRaw{};
  out.kind = esp::kFileIdDescriptorKind;
  for (std::size_t index = 0; index < 16; ++index) {
    std::string token = "0x";
    token.push_back(hex[index * 2]);
    token.push_back(hex[index * 2 + 1]);
    std::uint64_t byte = 0;
    if (!text::ParseUnsigned(token, byte) || byte > 255) {
      return false;
    }
    out.file_id[index] = static_cast<std::uint8_t>(byte);
  }
  return true;
}

constexpr DWORD kProcessCreateTriggerWaitMs = 2000;
constexpr std::wstring_view kCmdImagePath = L"C:\\Windows\\System32\\cmd.exe";

[[nodiscard]] bool IsWin32ImagePath(std::string_view path) noexcept {
  if (path.size() >= 3 && path[1] == ':' &&
      (path[2] == '\\' || path[2] == '/')) {
    return true;
  }
  return path.starts_with("\\\\");
}

[[nodiscard]] bool FilenameEqualsCmdExe(std::string_view path) noexcept {
  const std::size_t slash = path.find_last_of("\\/");
  const std::string_view name =
      slash == std::string_view::npos ? path : path.substr(slash + 1);
  return text::EqualsIgnoreCase(name, "cmd.exe");
}

[[nodiscard]] std::string_view Win32PathFromLeaf(std::string_view value) {
  std::string_view path = value;
  if (path.starts_with(esp::kNtPathPrefix)) {
    path = path.substr(esp::kNtPathPrefix.size());
  }
  if (IsWin32ImagePath(path)) {
    return path;
  }
  return {};
}

void FindProcessEqualsLeaf(const model::FilterNode& node, bool under_not,
                           std::string& found) {
  if (!found.empty()) {
    return;
  }
  if (node.kind == model::FilterKind::Not) {
    for (const model::FilterNode& child : node.children) {
      FindProcessEqualsLeaf(child, true, found);
    }
    return;
  }
  if (node.kind == model::FilterKind::Leaf) {
    if (!under_not && node.type == esp::kFilterCtorProcess &&
        node.comparand == static_cast<std::int32_t>(esp::kStringComparandMin) &&
        !node.value.empty()) {
      found = node.value;
    }
    return;
  }
  for (const model::FilterNode& child : node.children) {
    FindProcessEqualsLeaf(child, under_not, found);
  }
}

[[nodiscard]] std::string ProcessCreateEqualsImage(
    const model::RuleDocument& document) {
  std::string found;
  for (const model::RuleSpec& spec : document.rules) {
    if (spec.eventType != esp::kEventProcessCreate) {
      continue;
    }
    FindProcessEqualsLeaf(spec.filter, false, found);
    if (!found.empty()) {
      break;
    }
  }
  return found;
}

[[nodiscard]] bool SpawnProcessCreateTrigger(
    const model::RuleDocument& document, DWORD& child_pid,
    esptool::UniqueHandle& child_process) {
  child_pid = 0;
  child_process.reset();
  const std::string leaf = ProcessCreateEqualsImage(document);
  const std::string_view win32 = Win32PathFromLeaf(leaf);
  const bool use_cmd = leaf.empty() || FilenameEqualsCmdExe(leaf) ||
                       (!win32.empty() && FilenameEqualsCmdExe(win32));
  STARTUPINFOW info{};
  info.cb = sizeof(info);
  PROCESS_INFORMATION process{};
  BOOL created = FALSE;
  std::wstring image;
  std::wstring command;
  if (use_cmd) {
    image.assign(kCmdImagePath);
    command = L"C:\\Windows\\System32\\cmd.exe /c ping -n 20 127.0.0.1 >nul";
    created =
        CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &info, &process);
  } else if (!win32.empty()) {
    image = text::ToUtf16(win32);
    command = L"\"";
    command += image;
    command += L"\"";
    created =
        CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &info, &process);
  } else {
    image.assign(kCmdImagePath);
    command = L"C:\\Windows\\System32\\cmd.exe /c ping -n 20 127.0.0.1 >nul";
    created =
        CreateProcessW(image.c_str(), command.data(), nullptr, nullptr, FALSE,
                       CREATE_NO_WINDOW, nullptr, nullptr, &info, &process);
  }
  if (!created) {
    return false;
  }
  child_pid = process.dwProcessId;
  child_process.reset(process.hProcess);
  esptool::UniqueHandle thread_handle(process.hThread);
  return child_pid != 0;
}

[[nodiscard]] bool SpawnFoCreateTrigger(std::wstring& path_out) {
  wchar_t directory[MAX_PATH] = {};
  if (GetTempPathW(static_cast<DWORD>(std::size(directory)), directory) == 0) {
    return false;
  }
  wchar_t path[MAX_PATH] = {};
  if (GetTempFileNameW(directory, L"esp", 0, path) == 0) {
    return false;
  }
  esptool::UniqueHandle file(CreateFileW(path, GENERIC_WRITE, 0, nullptr,
                                         CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL,
                                         nullptr));
  if (!file) {
    return false;
  }
  file.reset();
  path_out.assign(path);
  return true;
}

[[nodiscard]] bool DocumentWantsFoTrigger(
    const model::RuleDocument& document) noexcept {
  return std::ranges::any_of(document.rules, [](const model::RuleSpec& spec) {
    return spec.eventType == esp::kEventFoCreate;
  });
}

void ApplyOptionalRefOps(esp::EspSession& session, const Options& options,
                         const std::string& kind, esp::ObjectReference& ref,
                         esp::EventObject view) {
  if (options.duplicate) {
    esp::ObjectReference copy;
    if (session.DuplicateReference(ref, copy)) {
      session.CloseReference(copy);
    }
  }
  std::vector<unsigned> ids;
  if (ParseCsvIds(options.properties, ids) && !ids.empty() && kind != "event") {
    (void)session.QueryKind(kind, view, ids.data(),
                            static_cast<unsigned>(ids.size()));
  }
  if (!options.supported.empty()) {
    std::uint64_t parsed = 0;
    if (text::ParseUnsigned(options.supported, parsed) &&
        parsed <= std::numeric_limits<unsigned>::max()) {
      std::uint32_t supported = 0;
      (void)session.IsPropertySupported(kind, static_cast<unsigned>(parsed),
                                        supported);
    }
  }
  if (options.context_set) {
    (void)session.SetEventObjectContextKey(ref);
  }
  if (options.context_enum) {
    (void)session.EnumerateEventObjectContextKeys(ref);
  }
}

[[nodiscard]] bool CreateReferenceForKind(esp::EspSession& session,
                                          const Options& options,
                                          const std::string& kind,
                                          esp::ObjectReference& ref) {
  if (kind == "process" || kind == "process-token") {
    const int pid = ResolvePid(options.pid);
    if (pid < 0) {
      return false;
    }
    const char* export_name = kind == "process"
                                  ? "EspCreateProcessReference"
                                  : "EspCreateProcessTokenReference";
    return session.CreatePidReference(export_name, pid, ref);
  }
  if (kind == "thread" || kind == "thread-token") {
    const int tid = ResolveTid(options.tid);
    if (tid < 0) {
      return false;
    }
    const char* export_name = kind == "thread"
                                  ? "EspCreateThreadReference"
                                  : "EspCreateThreadTokenReference";
    return session.CreatePidReference(export_name, tid, ref);
  }
  if (kind == "token") {
    if (!options.tid.empty() && options.pid.empty()) {
      const int tid = ResolveTid(options.tid);
      if (tid < 0) {
        return false;
      }
      return session.CreatePidReference("EspCreateThreadTokenReference", tid,
                                        ref);
    }
    const int pid = ResolvePid(options.pid);
    if (pid < 0) {
      return false;
    }
    return session.CreatePidReference("EspCreateProcessTokenReference", pid,
                                      ref);
  }
  if (kind == "desktop") {
    const std::wstring name = options.object_name.empty()
                                  ? std::wstring(L"Default")
                                  : text::ToUtf16(options.object_name);
    return session.CreateDesktopReference(name, ref);
  }
  if (kind == "volume") {
    esp::Guid volume{};
    if (!ParseGuidOption(options.volume, volume)) {
      return false;
    }
    return session.CreateVolumeReference(volume, ref);
  }
  if (kind == "registry") {
    if (options.path.empty()) {
      return false;
    }
    // Kind-1 path descriptor. Esp::EnsureNtRegistryPath expands HKLM\...
    // Pre-expanding to \Registry\Machine\... returns ERROR_BAD_PATHNAME.
    return session.CreatePathReference("EspCreateRegistryKeyReference",
                                       text::ToUtf16(options.path), ref);
  }
  if (kind == "disk") {
    if (options.path.empty()) {
      return false;
    }
    return session.CreatePathReference("EspCreateDiskReference",
                                       text::ToUtf16(options.path), ref);
  }
  if (kind == "pipe") {
    if (options.path.empty()) {
      return false;
    }
    return session.CreatePathReference("EspCreatePipeReference",
                                       text::ToUtf16(options.path), ref);
  }
  if (kind == "mailslot") {
    if (options.path.empty()) {
      return false;
    }
    return session.CreatePathReference("EspCreateMailslotReference",
                                       text::ToUtf16(options.path), ref);
  }
  if (kind == "file" || kind == "fileobject" || kind == "stream" ||
      kind == "filestream") {
    if (!options.file_id.empty()) {
      esp::Guid volume{};
      esp::FileIdDescriptorRaw file_id{};
      if (!ParseGuidOption(options.volume, volume) ||
          !ParseFileIdHex(options.file_id, file_id)) {
        return false;
      }
      if (kind == "stream" || kind == "filestream") {
        const std::wstring stream = text::ToUtf16(options.stream);
        return session.CreateStreamByIdReference(
            volume, file_id, stream.empty() ? nullptr : stream.c_str(), ref);
      }
      return session.CreateFileIdReference(volume, file_id, ref);
    }
    if (options.path.empty()) {
      return false;
    }
    const char* export_name = (kind == "stream" || kind == "filestream")
                                  ? "EspCreateFileStreamReferenceByPath"
                                  : "EspCreateFileReferenceByPath";
    return session.CreatePathReference(
        export_name, esp::ExpandFilterValue(options.path), ref);
  }
  if (kind == "event") {
    std::uint64_t event_id = 0;
    if (!text::ParseUnsigned(options.event_id, event_id) || event_id == 0) {
      return false;
    }
    return session.CreateEventObjectById(event_id, ref);
  }
  return false;
}

[[nodiscard]] int RunQuery(const esp::EspApi& api, const Options& options) {
  if (options.kind.empty()) {
    return RunConnectedAction(api, [](esp::EspSession& session) {
      (void)session.QueryAllProperties();
    });
  }
  const std::string kind = text::ToLowerAscii(options.kind);
  esp::EspSession session(api);
  const bool connected = session.Connect(UniqueClientSpec("esptool-query"));
  if (!connected) {
    ReportSession(session, false);
    session.Disconnect();
    return 1;
  }
  bool ok = false;
  esp::ObjectReference ref;
  esp::EventObject view;
  const std::string query_kind(esp::CanonicalQueryKind(kind));
  if (kind == "client") {
    if (options.properties.empty() && options.supported.empty()) {
      ReportSession(session, false);
      session.Disconnect();
      return Fail("query --kind client requires --properties or --supported");
    }
    std::vector<unsigned> ids;
    if (!options.properties.empty()) {
      if (!ParseCsvIds(options.properties, ids) || ids.empty()) {
        ReportSession(session, false);
        session.Disconnect();
        return Fail("invalid --properties");
      }
      (void)session.QueryKind(kind, view, ids.data(),
                              static_cast<unsigned>(ids.size()));
      ok = true;
    }
    if (!options.supported.empty()) {
      std::uint64_t parsed = 0;
      if (!text::ParseUnsigned(options.supported, parsed) ||
          parsed > std::numeric_limits<unsigned>::max()) {
        session.Disconnect();
        return Fail("invalid --supported");
      }
      std::uint32_t supported = 0;
      (void)session.IsPropertySupported(kind, static_cast<unsigned>(parsed),
                                        supported);
      ok = true;
    }
  } else if (esp::QueryExportForKind(kind) == nullptr ||
             !esp::KindHasReferenceCreate(kind)) {
    if (esp::QueryExportForKind(kind) == nullptr) {
      (void)session.QueryKind("event", view, nullptr, 0);
    }
    if (!options.supported.empty()) {
      std::uint64_t parsed = 0;
      if (!text::ParseUnsigned(options.supported, parsed) ||
          parsed > std::numeric_limits<unsigned>::max()) {
        session.Disconnect();
        return Fail("invalid --supported");
      }
      std::uint32_t supported = 0;
      (void)session.IsPropertySupported(
          query_kind, static_cast<unsigned>(parsed), supported);
      ok = true;
    }
    if (!options.properties.empty()) {
      std::fprintf(stderr,
                   "query --kind %s has no reference create; --properties "
                   "needs a view from refs or monitor\n",
                   kind.c_str());
    }
  } else {
    ok = CreateReferenceForKind(session, options, kind, ref);
    if (ok) {
      (void)session.UnwrapReference(ref, view);
      ApplyOptionalRefOps(session, options, query_kind, ref, view);
      session.CloseReference(ref);
    }
  }
  ReportSession(session, false);
  session.Disconnect();
  return ok ? 0 : 1;
}

[[nodiscard]] int RunRefs(const esp::EspApi& api, const Options& options) {
  std::string kind = text::ToLowerAscii(options.kind);
  if (kind.empty() && !options.positional.empty()) {
    kind = text::ToLowerAscii(options.positional[0]);
  }
  if (kind.empty()) {
    return Fail("refs requires a kind (process, file, event, ...)");
  }
  if (options.from_notify) {
    const auto parsed = LoadRuleDocument(options, "refs");
    if (!parsed) {
      return 1;
    }
    if (!parsed->ok) {
      return Fail(std::format("rule parse error: {}", parsed->error));
    }
    (void)CleanOrphanClients(api, options.fresh, "refs");
    esp::EspSession session(api);
    const RulesPrep prep =
        PrepareRulesSession(session, parsed->document, options);
    if (prep != RulesPrep::Ok) {
      ReportSession(session, true);
      session.Disconnect();
      return 1;
    }
    std::wstring fo_path;
    esptool::UniqueHandle child_process;
    if (DocumentWantsFoTrigger(parsed->document)) {
      if (SpawnFoCreateTrigger(fo_path)) {
        session.SetNotifyFallbackPath(fo_path);
      }
    } else {
      DWORD child_pid = 0;
      if (SpawnProcessCreateTrigger(parsed->document, child_pid,
                                    child_process)) {
        session.SetNotifyFallbackPid(static_cast<int>(child_pid));
      }
    }
    session.PumpNotifications(options.duration_ms, 1);
    if (parsed->document.rules.empty() ||
        std::ranges::all_of(
            parsed->document.rules,
            [](const model::RuleSpec& spec) { return spec.queries.empty(); })) {
      (void)session.QueryFromNotification();
    }
    ReportSession(session, true);
    session.Disconnect();
    if (child_process) {
      TerminateProcess(child_process.get(), 0);
      WaitForSingleObject(child_process.get(), kProcessCreateTriggerWaitMs);
    }
    if (!fo_path.empty()) {
      DeleteFileW(fo_path.c_str());
    }
    const bool created =
        std::ranges::any_of(session.Steps(), [](const esp::StepResult& step) {
          return step.ok && (step.step == "EspCreateProcessReference" ||
                             step.step == "EspCreateFileReferenceByPath" ||
                             step.step == "EspCreateEventObjectReferenceById");
        });
    return created ? 0 : 1;
  }

  esp::EspSession session(api);
  if (!session.Connect(UniqueClientSpec("esptool-refs"))) {
    ReportSession(session, false);
    session.Disconnect();
    return 1;
  }
  esp::ObjectReference ref;
  const bool created = CreateReferenceForKind(session, options, kind, ref);
  if (created) {
    std::printf("ref created kind=%s\n", kind.c_str());
    esp::EventObject view;
    (void)session.UnwrapReference(ref, view);
    if (view) {
      int type = 0;
      (void)session.GetEventObjectType(view, type);
      std::uint64_t id = 0;
      (void)session.GetEventObjectId(view, id);
    }
    ApplyOptionalRefOps(session, options,
                        std::string(esp::CanonicalQueryKind(kind)), ref, view);
    session.CloseReference(ref);
  }
  ReportSession(session, false);
  session.Disconnect();
  return created ? 0 : 1;
}

[[nodiscard]] int RunCollections(const esp::EspApi& api,
                                 const Options& options) {
  const bool extended = options.enum_ids || options.open_collection ||
                        options.collection_type_set || !options.guid.empty();
  if (!extended) {
    return RunConnectedAction(api, [](esp::EspSession& session) {
      (void)session.ExerciseCollections();
    });
  }
  esp::EspSession session(api);
  if (!session.Connect(model::ClientSpec{})) {
    ReportSession(session, false);
    session.Disconnect();
    return 1;
  }
  esp::Guid open_id{};
  const esp::Guid* open_ptr = nullptr;
  if (!options.guid.empty()) {
    if (!ParseGuidOption(options.guid, open_id)) {
      ReportSession(session, false);
      session.Disconnect();
      return Fail("invalid --guid");
    }
    open_ptr = &open_id;
  }
  const bool ok = session.ExerciseCollectionsExtended(
      static_cast<int>(options.collection_lifetime), options.enum_ids,
      options.open_collection || open_ptr != nullptr, open_ptr,
      options.collection_type);
  ReportSession(session, false);
  session.Disconnect();
  return ok ? 0 : 1;
}

[[nodiscard]] int RunContext(const esp::EspApi& api) {
  return RunConnectedAction(api, [](esp::EspSession& session) {
    (void)session.ExerciseContextKeys();
  });
}

[[nodiscard]] int RunExercise(const esp::EspApi& api, const Options& options) {
  esp::EspSession session(api);
  (void)session.Connect(model::ClientSpec{});
  esp::EspExercise exercise(api, session);
  const std::vector<esp::ExportOutcome> outcomes =
      options.isolated ? exercise.RunIsolated() : exercise.RunInProcess();

  PrintSeparator();
  std::printf("%-44s %-6s %-10s %-12s %-10s %s\n", "export", "arity",
              "resolved", "invoked", "result", "detail");
  std::size_t resolved = 0;
  std::size_t invoked = 0;
  std::size_t ok = 0;
  std::size_t failed = 0;
  std::size_t faulted = 0;
  for (const esp::ExportOutcome& outcome : outcomes) {
    if (outcome.resolved) {
      ++resolved;
    }
    if (outcome.invoked) {
      ++invoked;
    }
    if (outcome.invoked && outcome.result >= 0) {
      ++ok;
    }
    if (outcome.invoked && outcome.result < 0) {
      ++failed;
    }
    if (outcome.invoked && IsFault(outcome.result)) {
      ++faulted;
    }
    const esp::EspResult result = static_cast<esp::EspResult>(outcome.result);
    std::printf("%-44s %-6u %-10s %-12s %-10s %s\n", outcome.name.c_str(),
                static_cast<unsigned>(outcome.arity),
                outcome.resolved ? "resolved" : "unresolved",
                outcome.invoked ? "invoked" : "not-invoked",
                esp::HexResult(result).c_str(), outcome.detail.c_str());
  }
  PrintSeparator();
  std::printf(
      "total %zu, resolved %zu, invoked %zu, ok %zu, failed %zu, faulted %zu\n",
      outcomes.size(), resolved, invoked, ok, failed, faulted);
  session.Disconnect();
  return 0;
}

[[nodiscard]] int RunCallOne(const esp::EspApi& api, const Options& options) {
  if (options.positional.empty()) {
    std::fprintf(stderr, "call-one requires <name>\n");
    return 2;
  }
  esp::EspSession session(api);
  (void)session.Connect(model::ClientSpec{});
  const std::int64_t raw =
      esp::EspExercise::CallOne(api, session, options.positional[0]);
  const esp::EspResult result = static_cast<esp::EspResult>(raw);
  std::printf("%s %s %s\n", options.positional[0].c_str(),
              esp::HexResult(result).c_str(),
              esp::DescribeResult(result).c_str());
  session.Disconnect();
  return static_cast<int>(static_cast<std::uint32_t>(result));
}

[[nodiscard]] int RunToken(const Options& options) {
  if (options.positional.empty()) {
    std::fprintf(stderr, "token requires a subcommand: status|set|clear\n");
    return 2;
  }
  const std::string& sub = options.positional[0];
  if (sub == "status") {
    PrintTrustState();
    return 0;
  }

  std::string error;
  if (sub == "set") {
    unsigned permission = ResolvePermission(options);
    if (options.positional.size() >= 2) {
      const std::optional<unsigned> parsed =
          ParsePermission(options.positional[1]);
      if (!parsed) {
        std::fprintf(stderr, "unknown permission: %s\n",
                     options.positional[1].c_str());
        return 2;
      }
      permission = *parsed;
    }
    if (!ppl::SetWespPermission(permission, error)) {
      return Fail(error);
    }
    PrintTrustState();
    return 0;
  }
  if (sub == "clear") {
    if (!ppl::DeleteWespPermission(error)) {
      return Fail(error);
    }
    PrintTrustState();
    return 0;
  }
  std::fprintf(stderr, "unknown token subcommand: %s\n", sub.c_str());
  return 2;
}

[[nodiscard]] int RunProvision() {
  PrintTrustState();
  const bool ready = ppl::IsSystemAccount();
  ppl::TokenAttributeState attribute;
  std::string attribute_error;
  const bool have_attribute =
      ppl::QueryWespPermission(attribute, attribute_error);
  if (!ready || !have_attribute || !attribute.present) {
    return 1;
  }
  return 0;
}

[[nodiscard]] int RunPpl(const Options& options) {
  if (options.positional.empty()) {
    std::fprintf(stderr, "ppl requires a subcommand: status\n");
    return 2;
  }
  const std::string& sub = options.positional[0];
  if (sub == "status") {
    std::printf("ppl: %s\n", ppl::QueryCurrentProcess().Describe().c_str());
    return 0;
  }
  std::fprintf(stderr, "unknown ppl subcommand: %s\n", sub.c_str());
  return 2;
}

[[nodiscard]] int RunServiceCommand(const Options& options) {
  if (options.positional.empty()) {
    std::fprintf(stderr,
                 "service requires a subcommand: "
                 "install|uninstall|run|foreground\n");
    return 2;
  }
  const std::string& sub = options.positional[0];
  const std::wstring name = text::ToUtf16(options.service_name);
  std::string error;

  if (sub == "install") {
    const std::wstring executable = process::CurrentImagePath();
    if (executable.empty()) {
      std::fprintf(stderr, "could not resolve the executable path\n");
      return 1;
    }
    if (!ppl::Install(name, executable, name, options.no_provision, error)) {
      return Fail(error);
    }
    std::printf("service installed: %s\n", options.service_name.c_str());
    return 0;
  }
  if (sub == "uninstall") {
    if (!ppl::Uninstall(name, error)) {
      return Fail(error);
    }
    std::printf("service removed: %s\n", options.service_name.c_str());
    return 0;
  }
  if (sub == "foreground") {
    return ppl::RunForeground(name, !options.no_provision);
  }
  if (sub == "run") {
    const int dispatcher = ppl::RunService(name, !options.no_provision);
    if (dispatcher != 0) {
      std::fprintf(stderr, "service dispatcher failed (error %d)\n",
                   dispatcher);
      return 1;
    }
    return 0;
  }
  std::fprintf(stderr, "unknown service subcommand: %s\n", sub.c_str());
  return 2;
}

[[nodiscard]] int RunIpc(const Options& options) {
  if (options.positional.empty()) {
    std::fprintf(
        stderr,
        "ipc requires a subcommand: ping|status|exports|exercise|rules\n");
    return 2;
  }
  const std::string& sub = options.positional[0];
  ipc::RequestKind kind = ipc::RequestKind::Ping;
  std::string payload;
  if (sub == "ping") {
    kind = ipc::RequestKind::Ping;
  } else if (sub == "status") {
    kind = ipc::RequestKind::Status;
  } else if (sub == "exports") {
    kind = ipc::RequestKind::Exports;
  } else if (sub == "exercise") {
    kind = ipc::RequestKind::Exercise;
  } else if (sub == "rules") {
    if (options.rules_path.empty()) {
      std::fprintf(stderr, "ipc rules requires --rules <path>\n");
      return 2;
    }
    std::ifstream input(options.rules_path, std::ios::binary);
    if (!input) {
      std::fprintf(stderr, "could not open the rule file: %s\n",
                   options.rules_path.c_str());
      return 1;
    }
    payload.assign(std::istreambuf_iterator<char>(input),
                   std::istreambuf_iterator<char>());
    kind = ipc::RequestKind::Rules;
  } else {
    std::fprintf(stderr, "unknown ipc subcommand: %s\n", sub.c_str());
    return 2;
  }

  ipc::PipeClient client;
  std::string error;
  if (!client.Connect(text::ToUtf16(options.pipe_name), error)) {
    return Fail(error);
  }
  ipc::Request request;
  request.kind = kind;
  request.payload = payload;
  ipc::Response response;
  if (!client.Exchange(request, response, error)) {
    return Fail(error);
  }
  std::printf("status %d\n%s\n", static_cast<int>(response.status),
              response.payload.c_str());
  client.Close();
  return 0;
}

[[nodiscard]] int EnsureWorkerOrTcb(const Options& options,
                                    const TrustPlan& plan) {
  if (CommandNeedsWorker(options)) {
    return PrepareThisProcess(options, plan);
  }
  if (CommandNeedsSystemContext(options)) {
    return RequireTcbOrFail();
  }
  return 0;
}

[[nodiscard]] int DispatchLocal(const Options& options) {
  const std::string& command = options.command;
  if (command == "ppl") {
    return RunPpl(options);
  }
  if (command == "service") {
    return RunServiceCommand(options);
  }
  if (command == "ipc") {
    return RunIpc(options);
  }
  if (command == "token") {
    return RunToken(options);
  }
  if (command == "provision") {
    return RunProvision();
  }
  return -1;
}

[[nodiscard]] int DispatchEsp(const Options& options) {
  esp::EspApi api;
  const std::wstring explicit_path = options.dll_path.empty()
                                         ? std::wstring()
                                         : text::ToUtf16(options.dll_path);
  if (!api.Load(explicit_path)) {
    Log::Error(api.LastErrorMessage());
    std::fprintf(stderr, "%s\n", api.LastErrorMessage().c_str());
    return 2;
  }

  const std::string& command = options.command;
  if (command == "exports") {
    return RunExports(api);
  }
  if (command == "status") {
    return RunStatus(api);
  }
  if (command == "connect") {
    return RunConnect(api);
  }
  if (command == "rules") {
    return RunRules(api, options);
  }
  if (command == "monitor") {
    return RunMonitor(api, options);
  }
  if (command == "clients") {
    return RunClients(api);
  }
  if (command == "unregister") {
    return RunUnregister(api, options);
  }
  if (command == "enum-rules") {
    return RunEnumRules(api);
  }
  if (command == "remove-rules") {
    return RunRemoveRules(api);
  }
  if (command == "persist-rules") {
    return RunPersistRules(api, options);
  }
  if (command == "open-queue") {
    return RunOpenQueue(api);
  }
  if (command == "trust") {
    return RunTrust(api);
  }
  if (command == "query") {
    return RunQuery(api, options);
  }
  if (command == "refs") {
    return RunRefs(api, options);
  }
  if (command == "collections") {
    return RunCollections(api, options);
  }
  if (command == "context") {
    return RunContext(api);
  }
  if (command == "exercise") {
    return RunExercise(api, options);
  }
  if (command == "call-one") {
    return RunCallOne(api, options);
  }
  std::printf("%s\n", Usage().c_str());
  return 2;
}

}  // namespace

int Dispatch(const Options& options) {
  Options effective_options = options;

  const ProvisioningContext ctx = ProbeCurrentTrustContext();
  if (!ctx.probe_ok && CommandNeedsWorker(options)) {
    return Fail(std::format("trust probe failed: {}", ctx.error));
  }

  TrustPlan plan;
  std::string plan_error;
  if (!EvaluateTrustPlan(effective_options, ctx, plan, plan_error)) {
    return Fail(plan_error);
  }

  if (plan.auto_no_provision_applied) {
    effective_options.no_provision = true;
    if (Log::WouldLog(LogLevel::Info)) {
      Log::Info(
          "auto-provision: test-signing active on non-PPL process; "
          "automatic --no-provision selected");
    }
  }
  if (plan.clean_needed) {
    effective_options.clear_attribute = true;
  }

  if (plan.child_required && !effective_options.worker) {
    return HopToWorker(effective_options);
  }

  const int prepared = EnsureWorkerOrTcb(effective_options, plan);
  if (prepared != 0) {
    return prepared;
  }
  const int local = DispatchLocal(effective_options);
  if (local >= 0) {
    return local;
  }
  return DispatchEsp(effective_options);
}

}  // namespace esptool::cli
