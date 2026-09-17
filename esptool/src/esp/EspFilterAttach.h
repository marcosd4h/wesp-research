#pragma once

#include <cstddef>

#include "esp/EspEventIds.h"
#include "esp/EspFilterAbi.h"
#include "model/RuleDocument.h"

namespace esptool::esp {

[[nodiscard]] inline bool HasCtorLeaf(const model::FilterNode& node,
                                      std::int32_t ctor) noexcept {
  if (node.kind == model::FilterKind::Leaf) {
    return node.type == ctor;
  }
  for (const model::FilterNode& child : node.children) {
    if (HasCtorLeaf(child, ctor)) {
      return true;
    }
  }
  return false;
}

[[nodiscard]] inline bool HasRegistryKeyLeaf(
    const model::FilterNode& node) noexcept {
  return HasCtorLeaf(node, kFilterCtorRegistryKey);
}

[[nodiscard]] inline bool HasFileObjectLeaf(
    const model::FilterNode& node) noexcept {
  return HasCtorLeaf(node, kFilterCtorFileObject);
}

[[nodiscard]] inline bool HasProcessLeaf(
    const model::FilterNode& node) noexcept {
  return HasCtorLeaf(node, kFilterCtorProcess);
}

[[nodiscard]] constexpr std::size_t FilterDescriptorOffsetForCtor(
    std::int32_t ctor) noexcept {
  if (ctor == kFilterCtorProcess) {
    return kRuleProcessFilterOffset;
  }
  if (ctor == kFilterCtorEvent) {
    return kRuleEventFilterOffset;
  }
  return 0;
}

[[nodiscard]] inline std::size_t FilterRuleOffset(
    const model::FilterNode& node) noexcept {
  if (node.kind == model::FilterKind::Leaf) {
    return FilterDescriptorOffsetForCtor(node.type);
  }
  for (const model::FilterNode& child : node.children) {
    const std::size_t offset = FilterRuleOffset(child);
    if (offset != 0) {
      return offset;
    }
  }
  return 0;
}

[[nodiscard]] constexpr bool ShouldAttachRegistryConfig(
    std::uint32_t event_type, bool has_registry_leaf) noexcept {
  return IsRegistryEventType(event_type) && has_registry_leaf;
}

}  // namespace esptool::esp
