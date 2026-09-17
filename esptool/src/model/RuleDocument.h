#pragma once

#include <cstdint>
#include <optional>
#include <string>
#include <vector>

#include "esp/EspTypes.h"

namespace esptool::model {

// ABI values written at rule descriptor +24. 0 is tag 92.
enum class RuleLifetime : std::int32_t {
  Transient = 1,
  Persistent = 3,
};

// Node kind of a predicate tree.
enum class FilterKind {
  Leaf,
  And,
  Or,
  Xor,
  Not,
};

// A single predicate tree node.
//
// A leaf maps onto one typed filter constructor in espclient.dll. The typed
// constructors take an opaque selector pair (type, comparand) plus an operand
// blob, so the model keeps the raw values and carries the symbolic names only
// for readability in logs and reports.
struct FilterNode {
  FilterKind kind = FilterKind::Leaf;

  // Leaf fields.
  std::int32_t type = 0;
  std::int32_t comparand = 0;
  std::uint64_t operand = 0;
  std::uint32_t propertyId = 0;
  std::string propertyName;
  std::string opName;
  std::string value;
  std::string collectionName;

  std::vector<FilterNode> children;
};

struct QueryRecipe {
  std::string kind;
  std::vector<unsigned> properties;
  bool context_set = false;
  bool context_enum = false;
};

struct CollectionSpec {
  std::string name;
  std::uint32_t type = 2;
  bool open = false;
  esp::Guid guid{};
  bool hasGuid = false;
  std::vector<std::string> entries;
};

// One rule definition. InstallRules uses eventType, action (0 ->
// kActionQueueBacked), and filter.
struct RuleSpec {
  std::string name;
  std::uint32_t eventType = 0;
  std::string eventName;
  RuleLifetime lifetime = RuleLifetime::Transient;
  std::uint32_t flags = 0;
  std::uint64_t action = 0;
  // Named action token. "deny" selects the enforcing path (selector 5) with the
  // event-appropriate modify kind. "suppress" selects the notify-suppression
  // selector (4). Empty when the action was given numerically.
  std::string actionName;
  // Experiment and enforcement overrides. When unset, InstallRules derives the
  // value the same way it always has (selector from action, lifetime from the
  // lifetime attribute, modify kind from the event type).
  std::optional<std::uint32_t> selector_override;
  std::optional<std::uint32_t> modifier_override;
  std::optional<std::uint32_t> modify_kind_override;
  FilterNode filter;
  std::vector<QueryRecipe> queries;
};

// Client identity used for registration.
struct ClientSpec {
  std::string name = esp::kDefaultClientName;
  std::string altitude = esp::kDefaultClientAltitude;
  esp::Guid guid{};
  bool hasGuid = false;
};

// A parsed rule document. Either loaded from XML or built by the command line.
struct RuleDocument {
  ClientSpec client;
  std::vector<RuleSpec> rules;
  std::vector<CollectionSpec> collections;
  std::string sourcePath;
};

}  // namespace esptool::model
