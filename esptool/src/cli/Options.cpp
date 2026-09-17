#include "cli/Options.h"

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <format>
#include <limits>
#include <optional>
#include <ranges>
#include <string>
#include <string_view>

#include "ppl/Protection.h"
#include "ppl/TokenAttribute.h"
#include "util/StrHelpers.h"

namespace esptool::cli {
namespace {

// Matches an exact flag or a --flag=value form.
[[nodiscard]] bool IsFlag(std::string_view token,
                          std::string_view flag) noexcept {
  if (token == flag) {
    return true;
  }
  return token.starts_with(flag) && token.size() > flag.size() &&
         token[flag.size()] == '=';
}

// Reads a flag value from either the trailing =value or the next argument.
[[nodiscard]] bool TakeValue(int argc, wchar_t** argv, int& index,
                             std::string_view token, std::string_view flag,
                             std::string& value, std::string& error) {
  const std::size_t equals = token.find('=');
  if (equals != std::string_view::npos) {
    value.assign(token.substr(equals + 1));
    return true;
  }
  if (index + 1 >= argc) {
    error = std::format("missing value for {}", flag);
    return false;
  }
  ++index;
  value = text::ToUtf8(argv[index]);
  return true;
}

struct StringFlag {
  const char* flag;
  std::string Options::* field;
};

constexpr std::array kStringFlags = std::to_array<StringFlag>({
    {"--dll", &Options::dll_path},
    {"--rules", &Options::rules_path},
    {"--log", &Options::log_path},
    {"--pipe", &Options::pipe_name},
    {"--service", &Options::service_name},
    {"--level", &Options::level},
    {"--target", &Options::target},
    {"--permission", &Options::permission},
    {"--guid", &Options::guid},
    {"--kind", &Options::kind},
    {"--pid", &Options::pid},
    {"--tid", &Options::tid},
    {"--path", &Options::path},
    {"--file-id", &Options::file_id},
    {"--volume", &Options::volume},
    {"--stream", &Options::stream},
    {"--name", &Options::object_name},
    {"--event-id", &Options::event_id},
    {"--properties", &Options::properties},
    {"--supported", &Options::supported},
});

struct BoolFlag {
  const char* flag;
  bool Options::* field;
};

constexpr std::array kBoolFlags = std::to_array<BoolFlag>({
    {"--help", &Options::help},
    {"-h", &Options::help},
    {"--verbose", &Options::verbose},
    {"-v", &Options::verbose},
    {"--no-provision", &Options::no_provision},
    {"--no-auto-provision", &Options::no_auto_provision},
    {"--force-provision", &Options::force_provision},
    {"--force-hop", &Options::force_hop},
    {"--no-hop", &Options::no_hop},
    {"--clear-attribute", &Options::clear_attribute},
    {"--isolated", &Options::isolated},
    {"--json", &Options::json},
    {"--iocp", &Options::iocp},
    {"--enforce-compat", &Options::enforce_compat},
    {"--bypass-eventtype", &Options::bypass_eventtype},
    {"--fresh", &Options::fresh},
    {"--all", &Options::all},
    {"--from-notify", &Options::from_notify},
    {"--duplicate", &Options::duplicate},
    {"--context-set", &Options::context_set},
    {"--context-enum", &Options::context_enum},
    {"--enum-ids", &Options::enum_ids},
    {"--open", &Options::open_collection},
});

struct CountFlag {
  const char* flag;
  unsigned Options::* field;
};

constexpr std::array kCountFlags = std::to_array<CountFlag>({
    {"--duration", &Options::duration_ms},
    {"--max", &Options::max_notifications},
    {"--type", &Options::collection_type},
    {"--lifetime", &Options::collection_lifetime},
});

template <typename Flag, std::size_t N>
[[nodiscard]] const Flag* FindFlag(const std::array<Flag, N>& flags,
                                   std::string_view token) noexcept {
  const auto found = std::ranges::find_if(
      flags, [&](const Flag& entry) { return IsFlag(token, entry.flag); });
  return found != flags.end() ? &*found : nullptr;
}

[[nodiscard]] bool ParseCount(std::string_view value, unsigned& out) noexcept {
  std::uint64_t parsed = 0;
  if (!text::ParseUnsigned(value, parsed) ||
      parsed > std::numeric_limits<unsigned>::max()) {
    return false;
  }
  out = static_cast<unsigned>(parsed);
  return true;
}

}  // namespace

bool ParseOptions(int argc, wchar_t** argv, Options& out, std::string& error) {
  out = Options{};
  error.clear();
  if (argc > 1) {
    out.tokens.reserve(static_cast<std::size_t>(argc - 1));
    for (int index = 1; index < argc; ++index) {
      out.tokens.emplace_back(argv[index]);
    }
  }
  bool positional_only = false;
  for (int index = 1; index < argc; ++index) {
    const std::string token = text::ToUtf8(argv[index]);
    if (positional_only) {
      out.positional.push_back(token);
      continue;
    }
    if (token == "--") {
      positional_only = true;
      continue;
    }
    const bool looks_like_flag =
        !token.empty() && token[0] == '-' && token != "-";
    if (!looks_like_flag) {
      if (out.command.empty()) {
        out.command = token;
      } else {
        out.positional.push_back(token);
      }
      continue;
    }

    std::string value;
    if (const StringFlag* entry = FindFlag(kStringFlags, token)) {
      if (!TakeValue(argc, argv, index, token, entry->flag, value, error)) {
        return false;
      }
      out.*(entry->field) = value;
      continue;
    }
    if (const BoolFlag* entry = FindFlag(kBoolFlags, token)) {
      out.*(entry->field) = true;
      continue;
    }
    if (token == "--worker") {
      out.worker = true;
      continue;
    }
    if (const CountFlag* entry = FindFlag(kCountFlags, token)) {
      if (!TakeValue(argc, argv, index, token, entry->flag, value, error)) {
        return false;
      }
      if (!ParseCount(value, out.*(entry->field))) {
        error = std::format("invalid value for {}: {}", entry->flag, value);
        return false;
      }
      if (std::string_view(entry->flag) == "--duration") {
        out.duration_set = true;
      }
      if (std::string_view(entry->flag) == "--max") {
        out.max_notifications_set = true;
      }
      if (std::string_view(entry->flag) == "--type") {
        out.collection_type_set = true;
      }
      continue;
    }
    error = std::format("unknown option: {}", token);
    return false;
  }
  if (out.no_provision && out.force_provision) {
    error = "cannot specify both --no-provision and --force-provision";
    return false;
  }
  if (out.no_provision && !out.permission.empty()) {
    error = "cannot specify both --no-provision and --permission";
    return false;
  }
  if (out.no_hop && out.force_hop) {
    error = "cannot specify both --no-hop and --force-hop";
    return false;
  }
  if (!out.permission.empty()) {
    if (!text::EqualsIgnoreCase(out.permission, "full") &&
        !text::EqualsIgnoreCase(out.permission, "restricted") &&
        !text::EqualsIgnoreCase(out.permission, "abcd")) {
      std::uint64_t num = 0;
      if (!text::ParseUnsigned(out.permission, num) ||
          num > std::numeric_limits<unsigned>::max()) {
        error =
            std::format("invalid value for --permission: {}", out.permission);
        return false;
      }
    }
  }
  return true;
}

std::string Usage() {
  return std::format(
      "esptool - runtime linker and exerciser for espclient.dll\n"
      "\n"
      "usage: esptool <command> [options] [arguments]\n"
      "\n"
      "commands:\n"
      "  exports                    list the exports and their resolution "
      "state\n"
      "  status                     show the loaded library and the "
      "protection state\n"
      "  connect                    connect a client, create a queue, arm a "
      "notification\n"
      "  rules                      parse --rules and install the rule "
      "batch\n"
      "  monitor                    install --rules and wait for "
      "notifications\n"
      "  clients                    enumerate registered WESP clients\n"
      "  unregister                 EspUnregisterClient (--guid or --all)\n"
      "  enum-rules                 enumerate rule IDs for this client\n"
      "  remove-rules               remove all rules for this client\n"
      "  persist-rules              install --rules with lifetime FFI 3\n"
      "  open-queue                 EspGetEventQueueId then EspOpenEventQueue\n"
      "  trust                      print the connect-tier and open a session\n"
      "  query                      count-0 client smoke, or --kind query\n"
      "  refs <kind>                create an object reference and optional "
      "query\n"
      "  collections                create and exercise a collection\n"
      "  context                    exercise the client context keys\n"
      "  exercise                   sweep every export (--isolated for "
      "child processes)\n"
      "  call-one <name>            invoke one export with a classified "
      "argument vector\n"
      "  ppl status                 show the current process protection "
      "state\n"
      "  token status               show WESP://Permission on the current "
      "token\n"
      "  token set [full|restricted]  stamp WESP://Permission (requires "
      "SYSTEM + SeTcbPrivilege)\n"
      "  token clear                remove WESP://Permission (requires "
      "SYSTEM + SeTcbPrivilege)\n"
      "  provision                  stamp WESP://Permission and print trust "
      "state (requires SYSTEM)\n"
      "  service install            install a demand-start SYSTEM service\n"
      "  service uninstall          stop and delete the service\n"
      "  service run                run the service dispatcher\n"
      "  service foreground         run the serve loop without the service "
      "manager\n"
      "  ipc ping                   send a ping request to the service\n"
      "  ipc status                 ask the service for its protection "
      "state\n"
      "  ipc exports                ask the service for its export counts\n"
      "  ipc exercise               ask the service to run the export "
      "sweep\n"
      "  ipc rules <path>           send and install a rule document over "
      "the pipe\n"
      "\n"
      "options:\n"
      "  --dll <path>      espclient.dll to load (default: search order)\n"
      "  --rules <path>    XML rule document for the rules and monitor "
      "commands\n"
      "  --log <path>      append diagnostics to a UTF-8 log file\n"
      "  --pipe <name>     named pipe for the ipc and service commands "
      "(default esptool)\n"
      "  --service <name>  Windows service name (default esptool)\n"
      "  --level <level>   trace|debug|info|warn|error (default info)\n"
      "  --target <value>  reserved target selector\n"
      "  --duration <ms>   notification pump duration (default {})\n"
      "  --max <count>     maximum notifications to pump (default {})\n"
      "  --isolated        run the export sweep in one child process per "
      "export\n"
      "  --json            reserved for machine-readable output\n"
      "  --permission <p>  full|restricted (default: full when PPL-AM, else "
      "restricted)\n"
      "  --no-provision    do not stamp WESP://Permission\n"
      "  --no-auto-provision  disable automatic test-signing and "
      "token-attribute detection\n"
      "  --force-provision force stamping WESP://Permission even if "
      "test-signing is active\n"
      "  --force-hop       force spawning a child worker process\n"
      "  --no-hop          execute in current process without child hopping\n"
      "  --iocp            monitor via EspConnectEventQueueWithIocp flags "
      "0\n"
      "  --enforce-compat  patch espclient.dll EventModify::from_ffi in memory "
      "so a deny rule installs for the driver-ready event types the unpatched "
      "client refuses; a compat install is logged, not proven to deny\n"
      "  --guid <id>       client or collection GUID\n"
      "  --kind <name>     query/refs object kind\n"
      "  --pid/--tid       process or thread id (self = current)\n"
      "  --path <path>     file, registry, disk, pipe, or mailslot path\n"
      "  --file-id <hex>   FILE_ID_128 for ById creates\n"
      "  --volume <guid>   volume GUID for ById or volume refs\n"
      "  --stream <name>   optional NTFS stream name\n"
      "  --name <desktop>  desktop name for refs desktop\n"
      "  --event-id <id>   event-object id for refs event\n"
      "  --properties <id,id>  query property identifiers (count >= 1)\n"
      "  --supported <id>  EspIs*PropertySupported probe\n"
      "  --from-notify     refs event via one notify hop\n"
      "  --duplicate       duplicate the created reference\n"
      "  --context-set/--context-enum  event-object context keys\n"
      "  --type <1|2|3>    collection create value type\n"
      "  --lifetime <1|2|3>  EspEnumerateCollectionIds lifetime\n"
      "  --enum-ids        enumerate collection identifiers\n"
      "  --open            EspOpenCollection in the same session\n"
      "  --all             unregister every enumerated client\n"
      "  --worker          this process is the worker child (do not "
      "relaunch)\n"
      "  --verbose, -v     enable debug diagnostics\n"
      "  --help, -h        show this text\n",
      kDefaultDurationMs, kDefaultMaxNotifications);
}

std::optional<unsigned> ParsePermission(std::string_view value) {
  if (text::EqualsIgnoreCase(value, "full")) {
    return ppl::kWespPermissionFull;
  }
  if (text::EqualsIgnoreCase(value, "restricted")) {
    return ppl::kWespPermissionRestricted;
  }
  if (text::EqualsIgnoreCase(value, "abcd")) {
    return ppl::kWespPermissionAbcdDeny;
  }
  std::uint64_t parsed = 0;
  if (text::ParseUnsigned(value, parsed) &&
      parsed <= std::numeric_limits<unsigned>::max()) {
    return static_cast<unsigned>(parsed);
  }
  return std::nullopt;
}

[[nodiscard]] unsigned ResolvePermission(const Options& options,
                                         const ProvisioningContext* ctx) {
  if (const std::optional<unsigned> parsed =
          ParsePermission(options.permission)) {
    return *parsed;
  }
  const bool is_ppl = ctx != nullptr
                          ? ctx->is_ppl
                          : ppl::QueryCurrentProcess().IsAntimalwareLight();
  return is_ppl ? ppl::kWespPermissionFull : ppl::kWespPermissionRestricted;
}

unsigned ResolvePermission(const Options& options) {
  return ResolvePermission(options, nullptr);
}

bool CommandNeedsWorker(const Options& options) {
  constexpr std::string_view kWorkerCommands[] = {
      "connect",    "rules",        "monitor",       "query",
      "refs",       "collections",  "context",       "exercise",
      "call-one",   "provision",    "clients",       "unregister",
      "enum-rules", "remove-rules", "persist-rules", "open-queue",
      "trust",
  };
  return std::ranges::find(kWorkerCommands, options.command) !=
         std::end(kWorkerCommands);
}

bool EvaluateTrustPlan(const Options& options, const ProvisioningContext& ctx,
                       TrustPlan& plan, std::string& error) {
  error.clear();
  plan = TrustPlan{};

  // 1. Determine effective no_provision
  if (options.no_provision) {
    plan.effective_no_provision = true;
    plan.reason = "explicit --no-provision";
  } else if (options.force_provision || !options.permission.empty()) {
    plan.effective_no_provision = false;
    plan.target_permission = ResolvePermission(options, &ctx);
    plan.reason = "explicit permission requested";
  } else if (options.no_auto_provision) {
    plan.effective_no_provision = false;
    plan.target_permission = ResolvePermission(options, &ctx);
    plan.reason = "auto-provision disabled via --no-auto-provision";
  } else {
    // Default: automatic detection based on system code integrity and PPL
    // status
    if (ctx.test_signing && !ctx.is_ppl && options.command != "provision") {
      plan.effective_no_provision = true;
      plan.auto_no_provision_applied = true;
      plan.reason =
          "test-signing active on non-PPL process (automatic --no-provision)";
    } else {
      plan.effective_no_provision = false;
      plan.target_permission = ResolvePermission(options, &ctx);
      plan.reason = "production trust required (PPL or test-signing inactive)";
    }
  }

  // 2. Evaluate token state and whether stamping or cleanup is needed
  if (plan.effective_no_provision) {
    plan.stamp_needed = false;
    // If the token currently has an inherited WESP://Permission attribute on a
    // test-signed non-PPL system, Gate D will fail unless it is removed!
    if (ctx.attribute_present && ctx.test_signing && !ctx.is_ppl) {
      plan.clean_needed = true;
    }
  } else if (CommandNeedsWorker(options)) {
    const bool already_has_exact_perm =
        ctx.attribute_present &&
        (ctx.attribute_permission == plan.target_permission);
    if (already_has_exact_perm) {
      plan.stamp_needed = false;
    } else {
      plan.stamp_needed = true;
    }
  }

  // 3. Complete Precedence Table for Child Worker Requirement:
  if (options.worker) {
    plan.child_required = false;
  } else if (options.no_hop) {
    plan.child_required = false;
  } else if (options.force_hop) {
    plan.child_required = CommandNeedsWorker(options);
  } else if (!CommandNeedsWorker(options)) {
    plan.child_required = false;
  } else if (plan.stamp_needed) {
    plan.child_required = true;
  } else if (plan.clean_needed) {
    plan.child_required = true;
  } else {
    plan.child_required = false;
  }

  return true;
}

}  // namespace esptool::cli
