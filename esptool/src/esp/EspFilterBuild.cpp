#include <charconv>

#include "esp/EspCatalog.h"
#include "esp/EspNtPath.h"
#include "esp/EspSession.h"
#include "esp/EspStatus.h"
#include "util/StrHelpers.h"

namespace esptool::esp {
namespace {

[[nodiscard]] const char* TypedFilterExportName(std::size_t selector) noexcept {
  if (selector == 0 || selector >= kTypedFilterExports.size()) {
    return nullptr;
  }
  return kTypedFilterExports[selector];
}

[[nodiscard]] std::uint32_t LeafProperty(
    const model::FilterNode& node) noexcept {
  return node.propertyId != 0 ? node.propertyId
                              : static_cast<std::uint32_t>(node.operand);
}

[[nodiscard]] bool FillNumericComparand(const model::FilterNode& node,
                                        NumericComparandRaw& blob) noexcept {
  if (node.comparand < static_cast<int>(kNumericOperatorMin) ||
      node.comparand > static_cast<int>(kNumericOperatorMax) ||
      node.value.empty()) {
    return false;
  }
  std::uint64_t numeric = 0;
  const char* first = node.value.data();
  const char* last = first + node.value.size();
  const auto parsed = std::from_chars(first, last, numeric);
  if (parsed.ec != std::errc{} || parsed.ptr != last) {
    return false;
  }
  blob = {};
  blob.comparison = static_cast<std::uint32_t>(node.comparand);
  blob.rhs_kind = kNumericRhsKindImmediate;
  blob.value = numeric;
  return true;
}

[[nodiscard]] bool FillStringComparand(const model::FilterNode& node,
                                       std::wstring& wide,
                                       StringComparandRaw& blob) {
  if (node.comparand < static_cast<int>(kStringComparandMin) ||
      node.comparand > static_cast<int>(kStringComparandMax) ||
      node.value.empty()) {
    return false;
  }
  wide = ExpandFilterValue(node.value);
  const std::uint64_t utf16_bytes = wide.size() * sizeof(wchar_t);
  if (wide.empty() || utf16_bytes > kMaxUtf16Bytes) {
    return false;
  }
  blob = {};
  blob.comparison = static_cast<std::uint32_t>(node.comparand);
  blob.string_kind = kStringKindInlineUtf16;
  blob.utf16_bytes = utf16_bytes;
  blob.text = wide.c_str();
  return true;
}

[[nodiscard]] const char* BinaryFilterExport(model::FilterKind kind) noexcept {
  if (kind == model::FilterKind::And) {
    return "EspCreateAndFilter";
  }
  if (kind == model::FilterKind::Or) {
    return "EspCreateOrFilter";
  }
  return "EspCreateXorFilter";
}

}  // namespace

EspResult EspSession::CreateLeafFilter(const model::FilterNode& node,
                                       Filter& out_filter) {
  out_filter.reset();
  const char* export_name =
      TypedFilterExportName(static_cast<std::size_t>(node.type));
  if (export_name == nullptr) {
    return kInvalidArg;
  }
  const auto fn = RequireTyped<CreateTypedFilterFn>(export_name);
  if (fn == nullptr) {
    return kInvalidArg;
  }
  const std::uint32_t property = LeafProperty(node);
  if (property == 0) {
    return kInvalidArg;
  }
  const auto invoke = [&](int size_class, auto& payload) -> EspResult {
    void* raw = nullptr;
    const EspResult result =
        fn(static_cast<int>(property), size_class, &payload, &raw);
    out_filter = Filter{raw};
    return result;
  };
  if (node.comparand == static_cast<int>(kStringComparandCollection)) {
    if (!IsObservedStringProperty(node.type, property)) {
      return kInvalidArg;
    }
    Collection collection;
    if (!node.collectionName.empty()) {
      collection = FindNamedCollection(node.collectionName);
      if (!collection) {
        return kInvalidArg;
      }
    } else if (node.value.empty() ||
               !CreateStringCollection(ExpandFilterValue(node.value),
                                       collection) ||
               !collection) {
      return kInvalidArg;
    }
    CollectionComparandRaw blob{};
    blob.comparison = kStringComparandCollection;
    blob.collection = collection.abi();
    collection_blobs_.push_back(blob);
    return invoke(kStringPayloadSizeClass, collection_blobs_.back());
  }
  if (IsObservedNumericProperty(node.type, property)) {
    NumericComparandRaw blob{};
    if (!FillNumericComparand(node, blob)) {
      return kInvalidArg;
    }
    numeric_blobs_.push_back(blob);
    return invoke(kNumericPayloadSizeClass, numeric_blobs_.back());
  }
  if (IsObservedBoolProperty(node.type, property)) {
    BoolComparandRaw blob{};
    blob.comparison = kBoolComparandEquals;
    blob.rhs_kind = kBoolRhsKindImmediate;
    blob.value =
        (node.value == "1" || text::EqualsIgnoreCase(node.value, "true")) ? 1u
                                                                          : 0u;
    bool_blobs_.push_back(blob);
    return invoke(kBoolPayloadSizeClass, bool_blobs_.back());
  }
  if (!IsObservedStringProperty(node.type, property)) {
    return kInvalidArg;
  }
  filter_strings_.emplace_back();
  StringComparandRaw blob{};
  if (!FillStringComparand(node, filter_strings_.back(), blob)) {
    filter_strings_.pop_back();
    return kInvalidArg;
  }
  blob.text = filter_strings_.back().c_str();
  if (node.type == kFilterCtorFile && property == 17) {
    FilePathComparandRaw wrapped{};
    wrapped.kind = kFilePathWrapperKind;
    wrapped.string = blob;
    file_path_blobs_.push_back(wrapped);
    return invoke(kFilePathPayloadSizeClass, file_path_blobs_.back());
  }
  filter_blobs_.push_back(blob);
  return invoke(kStringPayloadSizeClass, filter_blobs_.back());
}

EspResult EspSession::CreateBinaryFilter(model::FilterKind kind, Filter left,
                                         Filter right, Filter& out_filter) {
  const auto fn = RequireTyped<CreateBinaryFilterFn>(BinaryFilterExport(kind));
  if (fn == nullptr) {
    return kInvalidArg;
  }
  void* raw = nullptr;
  const EspResult result =
      fn(AsSharedWrapper(left), AsSharedWrapper(right), &raw);
  out_filter = Filter{raw};
  filters_.push_back(left);
  filters_.push_back(right);
  return result;
}

EspResult EspSession::CreateNotFilter(Filter child, Filter& out_filter) {
  const auto fn = RequireTyped<CreateNotFilterFn>("EspCreateNotFilter");
  if (fn == nullptr) {
    return kInvalidArg;
  }
  void* raw = nullptr;
  const EspResult result = fn(AsSharedWrapper(child), &raw);
  out_filter = Filter{raw};
  filters_.push_back(child);
  return result;
}

EspResult EspSession::CreateFilterTree(const model::FilterNode& node,
                                       Filter& out_filter) {
  out_filter.reset();
  switch (node.kind) {
    case model::FilterKind::Leaf:
      return CreateLeafFilter(node, out_filter);
    case model::FilterKind::And:
    case model::FilterKind::Or:
    case model::FilterKind::Xor: {
      if (node.children.size() < 2) {
        return kInvalidArg;
      }
      Filter left;
      EspResult result = CreateFilterTree(node.children[0], left);
      if (Failed(result)) {
        return result;
      }
      Filter right;
      result = CreateFilterTree(node.children[1], right);
      if (Failed(result)) {
        if (const auto close_fn =
                RequireTyped<CloseFilterFn>("EspCloseFilter")) {
          close_fn(AsSharedWrapper(left));
        }
        return result;
      }
      return CreateBinaryFilter(node.kind, left, right, out_filter);
    }
    case model::FilterKind::Not: {
      if (node.children.size() != 1) {
        return kInvalidArg;
      }
      Filter child;
      const EspResult result = CreateFilterTree(node.children[0], child);
      if (Failed(result)) {
        return result;
      }
      return CreateNotFilter(child, out_filter);
    }
  }
  return kInvalidArg;
}

}  // namespace esptool::esp
