#include <doctest.h>

#include "esp/EspRuleAbi.h"

TEST_CASE("ActionNeedsQueue is true for action 0, 1, and kActionQueueBacked") {
  using esptool::esp::ActionNeedsQueue;
  using esptool::esp::kActionQueueBacked;

  CHECK(ActionNeedsQueue(0));
  CHECK(ActionNeedsQueue(1));
  CHECK(ActionNeedsQueue(kActionQueueBacked));
  CHECK(ActionNeedsQueue(0x100000001ull));  // truncates to 1
}

TEST_CASE("ActionNeedsQueue is false for deny, rewrite, cancel, and match-subrules") {
  using esptool::esp::ActionNeedsQueue;
  using esptool::esp::kActionCancel;
  using esptool::esp::kActionDeny;
  using esptool::esp::kActionMatchSubrules;
  using esptool::esp::kActionRewrite;

  CHECK_FALSE(ActionNeedsQueue(kActionDeny));
  CHECK_FALSE(ActionNeedsQueue(kActionRewrite));
  CHECK_FALSE(ActionNeedsQueue(kActionCancel));
  CHECK_FALSE(ActionNeedsQueue(kActionMatchSubrules));
  CHECK_FALSE(ActionNeedsQueue(1ull << 32));  // truncates to 0 but action!=0 so NOT defaulted
}

TEST_CASE("ActionSelectorForName maps the named actions to their selectors") {
  using esptool::esp::ActionNeedsQueue;
  using esptool::esp::ActionNeedsQueueFor;
  using esptool::esp::ActionSelectorForName;
  using esptool::esp::kActionDeny;
  using esptool::esp::kActionNotifySuppress;
  using esptool::esp::kActionQueueBacked;
  using esptool::esp::kActionRewrite;

  // The deny action is the enforcing selector. A regression that re-maps deny to
  // selector 4, which is the original defect, fails these assertions.
  CHECK(kActionDeny == kActionRewrite);
  CHECK(ActionSelectorForName("deny", kActionQueueBacked) == kActionRewrite);
  CHECK(ActionSelectorForName("deny", kActionQueueBacked) != kActionNotifySuppress);
  CHECK(ActionSelectorForName("suppress", kActionQueueBacked) ==
        kActionNotifySuppress);
  CHECK(ActionSelectorForName("", kActionRewrite) == kActionRewrite);
  CHECK(ActionSelectorForName("unknown", 9u) == 9u);

  // Named deny and suppress are non-queue actions even though the numeric action
  // field is zero, which the raw-action predicate classifies as queue-backed.
  CHECK(ActionNeedsQueue(0));
  CHECK_FALSE(ActionNeedsQueueFor(0, "deny"));
  CHECK_FALSE(ActionNeedsQueueFor(0, "suppress"));
  CHECK(ActionNeedsQueueFor(0, ""));
  CHECK_FALSE(ActionNeedsQueueFor(1, "deny"));
  CHECK_FALSE(ActionNeedsQueueFor(5, "deny"));

  // The queue requirement follows the selector that is actually installed, so a
  // selector override is authoritative.
  using esptool::esp::ResolvedActionNeedsQueue;
  CHECK_FALSE(ResolvedActionNeedsQueue(0, "", std::optional<std::uint32_t>{5}));
  CHECK_FALSE(ResolvedActionNeedsQueue(0, "", std::optional<std::uint32_t>{6}));
  CHECK_FALSE(ResolvedActionNeedsQueue(0, "", std::optional<std::uint32_t>{4}));
  CHECK(ResolvedActionNeedsQueue(0, "", std::optional<std::uint32_t>{1}));
  CHECK(ResolvedActionNeedsQueue(0, "", std::nullopt));
  CHECK_FALSE(ResolvedActionNeedsQueue(0, "deny", std::nullopt));
}
