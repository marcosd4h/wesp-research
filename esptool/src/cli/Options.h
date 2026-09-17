#pragma once

#include <optional>
#include <string>
#include <string_view>
#include <vector>

#include "esp/EspCore.h"

namespace esptool::cli {

constexpr unsigned kDefaultDurationMs = 5000;
constexpr unsigned kDefaultMaxNotifications = 10;

// Parsed command line.
struct Options {
  std::string command;
  std::vector<std::string> positional;
  std::string dll_path;
  std::string rules_path;
  std::string log_path;
  std::string pipe_name = esp::kDefaultClientName;
  std::string service_name = esp::kDefaultClientName;
  std::string level;
  std::string target;
  std::string permission;
  std::string guid;
  std::string kind;
  std::string pid;
  std::string tid;
  std::string path;
  std::string file_id;
  std::string volume;
  std::string stream;
  std::string object_name;
  std::string event_id;
  std::string properties;
  std::string supported;
  unsigned duration_ms = kDefaultDurationMs;
  unsigned max_notifications = kDefaultMaxNotifications;
  unsigned collection_type = 2;
  unsigned collection_lifetime = 1;
  bool duration_set = false;
  bool max_notifications_set = false;
  bool collection_type_set = false;
  bool isolated = false;
  bool json = false;
  bool help = false;
  bool verbose = false;
  bool no_provision = false;
  bool no_auto_provision = false;
  bool force_provision = false;
  bool force_hop = false;
  bool no_hop = false;
  bool clear_attribute = false;
  bool iocp = false;
  bool enforce_compat = false;
  bool bypass_eventtype = false;
  bool fresh = false;
  bool worker = false;
  bool all = false;
  bool from_notify = false;
  bool duplicate = false;
  bool context_set = false;
  bool context_enum = false;
  bool enum_ids = false;
  bool open_collection = false;
  std::vector<std::wstring> tokens;
};

// Parses the wide command line. Returns false and fills error when an option is
// unknown or a value is missing or malformed.
[[nodiscard]] bool ParseOptions(int argc, wchar_t** argv, Options& out,
                                std::string& error);

// Multi-line usage text listing every command and option.
[[nodiscard]] std::string Usage();

struct ProvisioningContext {
  bool is_system = false;
  bool is_tcb = false;
  bool is_ppl = false;
  bool test_signing = false;
  bool attribute_present = false;
  unsigned attribute_permission = 0;
  bool probe_ok = false;
  std::string error;
};

struct TrustPlan {
  bool effective_no_provision = false;
  bool auto_no_provision_applied = false;
  bool stamp_needed = false;
  bool clean_needed = false;
  bool child_required = false;
  unsigned target_permission = 0;
  std::string reason;
};

[[nodiscard]] std::optional<unsigned> ParsePermission(std::string_view value);
[[nodiscard]] unsigned ResolvePermission(const Options& options);
[[nodiscard]] bool CommandNeedsWorker(const Options& options);

[[nodiscard]] bool EvaluateTrustPlan(const Options& options,
                                     const ProvisioningContext& ctx,
                                     TrustPlan& plan, std::string& error);

}  // namespace esptool::cli
