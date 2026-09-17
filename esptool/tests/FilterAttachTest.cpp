#include <doctest.h>

#include <cstddef>
#include <vector>

#include "esp/EspFilterAttach.h"
#include "model/RuleDocument.h"
#include "esp/EspFilterAbi.h"
#include "esp/EspEventIds.h"

namespace {

esptool::model::FilterNode MakeLeaf(std::int32_t ctor) {
  esptool::model::FilterNode node;
  node.kind = esptool::model::FilterKind::Leaf;
  node.type = ctor;
  return node;
}

esptool::model::FilterNode MakeCombo(
    esptool::model::FilterKind kind,
    std::vector<esptool::model::FilterNode> children) {
  esptool::model::FilterNode node;
  node.kind = kind;
  node.children = std::move(children);
  return node;
}

}  // namespace

TEST_CASE("Has*Leaf walks nested and or not trees") {
  using esptool::esp::HasCtorLeaf;
  using esptool::esp::HasFileObjectLeaf;
  using esptool::esp::HasProcessLeaf;
  using esptool::esp::HasRegistryKeyLeaf;
  using esptool::esp::kFilterCtorEvent;
  using esptool::esp::kFilterCtorFileObject;
  using esptool::esp::kFilterCtorProcess;
  using esptool::esp::kFilterCtorRegistryKey;
  using esptool::model::FilterKind;

  const esptool::model::FilterNode and_tree = MakeCombo(
      FilterKind::And, {MakeLeaf(kFilterCtorEvent), MakeLeaf(kFilterCtorProcess)});
  CHECK(HasProcessLeaf(and_tree));
  CHECK(HasCtorLeaf(and_tree, kFilterCtorEvent));
  CHECK_FALSE(HasFileObjectLeaf(and_tree));
  CHECK_FALSE(HasRegistryKeyLeaf(and_tree));

  const esptool::model::FilterNode or_tree = MakeCombo(
      FilterKind::Or,
      {MakeLeaf(kFilterCtorFileObject), MakeLeaf(kFilterCtorEvent)});
  CHECK(HasFileObjectLeaf(or_tree));
  CHECK_FALSE(HasProcessLeaf(or_tree));
  CHECK_FALSE(HasRegistryKeyLeaf(or_tree));

  const esptool::model::FilterNode not_tree =
      MakeCombo(FilterKind::Not, {MakeLeaf(kFilterCtorRegistryKey)});
  CHECK(HasRegistryKeyLeaf(not_tree));
  CHECK_FALSE(HasProcessLeaf(not_tree));
  CHECK_FALSE(HasFileObjectLeaf(not_tree));

  const esptool::model::FilterNode nested = MakeCombo(
      FilterKind::And,
      {MakeCombo(FilterKind::Or,
                 {MakeCombo(FilterKind::Not, {MakeLeaf(kFilterCtorProcess)}),
                  MakeLeaf(kFilterCtorEvent)}),
       MakeCombo(FilterKind::Or, {MakeLeaf(kFilterCtorFileObject)})});
  CHECK(HasProcessLeaf(nested));
  CHECK(HasFileObjectLeaf(nested));
  CHECK(HasCtorLeaf(nested, kFilterCtorEvent));
  CHECK_FALSE(HasRegistryKeyLeaf(nested));

  const esptool::model::FilterNode empty_and =
      MakeCombo(FilterKind::And, {});
  CHECK_FALSE(HasProcessLeaf(empty_and));
  CHECK_FALSE(HasFileObjectLeaf(empty_and));
  CHECK_FALSE(HasRegistryKeyLeaf(empty_and));
  CHECK_FALSE(HasCtorLeaf(empty_and, kFilterCtorProcess));
}

TEST_CASE("FilterDescriptorOffsetForCtor maps process event and others") {
  using esptool::esp::FilterDescriptorOffsetForCtor;
  using esptool::esp::kFilterCtorClient;
  using esptool::esp::kFilterCtorEvent;
  using esptool::esp::kFilterCtorFileObject;
  using esptool::esp::kFilterCtorProcess;
  using esptool::esp::kFilterCtorRegistryKey;

  CHECK(FilterDescriptorOffsetForCtor(kFilterCtorProcess) == std::size_t{688});
  CHECK(FilterDescriptorOffsetForCtor(kFilterCtorEvent) == std::size_t{40});
  CHECK(FilterDescriptorOffsetForCtor(kFilterCtorFileObject) == std::size_t{0});
  CHECK(FilterDescriptorOffsetForCtor(kFilterCtorRegistryKey) ==
        std::size_t{0});
  CHECK(FilterDescriptorOffsetForCtor(kFilterCtorClient) == std::size_t{0});
  CHECK(FilterDescriptorOffsetForCtor(0) == std::size_t{0});
}

TEST_CASE("FilterRuleOffset walks children for the first non-zero offset") {
  using esptool::esp::FilterRuleOffset;
  using esptool::esp::kFilterCtorEvent;
  using esptool::esp::kFilterCtorFileObject;
  using esptool::esp::kFilterCtorProcess;
  using esptool::esp::kFilterCtorRegistryKey;
  using esptool::esp::kRuleEventFilterOffset;
  using esptool::esp::kRuleProcessFilterOffset;
  using esptool::model::FilterKind;

  CHECK(FilterRuleOffset(MakeLeaf(kFilterCtorProcess)) ==
        kRuleProcessFilterOffset);
  CHECK(FilterRuleOffset(MakeLeaf(kFilterCtorEvent)) == kRuleEventFilterOffset);
  CHECK(FilterRuleOffset(MakeLeaf(kFilterCtorFileObject)) == std::size_t{0});
  CHECK(FilterRuleOffset(MakeLeaf(kFilterCtorRegistryKey)) == std::size_t{0});

  const esptool::model::FilterNode file_then_process = MakeCombo(
      FilterKind::And,
      {MakeLeaf(kFilterCtorFileObject), MakeLeaf(kFilterCtorProcess)});
  CHECK(FilterRuleOffset(file_then_process) == kRuleProcessFilterOffset);

  const esptool::model::FilterNode process_then_event = MakeCombo(
      FilterKind::Or,
      {MakeLeaf(kFilterCtorProcess), MakeLeaf(kFilterCtorEvent)});
  CHECK(FilterRuleOffset(process_then_event) == kRuleProcessFilterOffset);

  const esptool::model::FilterNode event_then_process = MakeCombo(
      FilterKind::Or,
      {MakeLeaf(kFilterCtorEvent), MakeLeaf(kFilterCtorProcess)});
  CHECK(FilterRuleOffset(event_then_process) == kRuleEventFilterOffset);

  const esptool::model::FilterNode nested = MakeCombo(
      FilterKind::And,
      {MakeCombo(FilterKind::Not, {MakeLeaf(kFilterCtorRegistryKey)}),
       MakeCombo(FilterKind::Or, {MakeLeaf(kFilterCtorEvent)})});
  CHECK(FilterRuleOffset(nested) == kRuleEventFilterOffset);

  const esptool::model::FilterNode not_process =
      MakeCombo(FilterKind::Not, {MakeLeaf(kFilterCtorProcess)});
  CHECK(FilterRuleOffset(not_process) == kRuleProcessFilterOffset);

  const esptool::model::FilterNode empty = MakeCombo(FilterKind::And, {});
  CHECK(FilterRuleOffset(empty) == std::size_t{0});
}

TEST_CASE("ShouldAttachRegistryConfig requires registry event and leaf") {
  using esptool::esp::IsRegistryEventType;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventRegCreateKey;
  using esptool::esp::kEventRegMax;
  using esptool::esp::ShouldAttachRegistryConfig;

  CHECK(IsRegistryEventType(kEventRegCreateKey));
  CHECK(IsRegistryEventType(kEventRegMax));
  CHECK_FALSE(IsRegistryEventType(kEventProcessCreate));
  CHECK_FALSE(IsRegistryEventType(kEventRegCreateKey - 1));
  CHECK_FALSE(IsRegistryEventType(kEventRegMax + 1));

  CHECK(ShouldAttachRegistryConfig(kEventRegCreateKey, true));
  CHECK(ShouldAttachRegistryConfig(kEventRegMax, true));
  CHECK(ShouldAttachRegistryConfig(7007, true));

  CHECK_FALSE(ShouldAttachRegistryConfig(kEventRegCreateKey, false));
  CHECK_FALSE(ShouldAttachRegistryConfig(kEventRegMax, false));
  CHECK_FALSE(ShouldAttachRegistryConfig(kEventProcessCreate, true));
  CHECK_FALSE(ShouldAttachRegistryConfig(kEventProcessCreate, false));
  CHECK_FALSE(ShouldAttachRegistryConfig(kEventRegCreateKey - 1, true));
  CHECK_FALSE(ShouldAttachRegistryConfig(kEventRegMax + 1, true));
  CHECK_FALSE(ShouldAttachRegistryConfig(0, true));
}
