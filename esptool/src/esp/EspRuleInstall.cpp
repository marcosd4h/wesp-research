#include <algorithm>
#include <bit>
#include <cstddef>
#include <format>

#include "esp/EspEnforceCompat.h"
#include "esp/EspEventConfigAbi.h"
#include "esp/EspFilterAttach.h"
#include "esp/EspMemoryView.h"
#include "esp/EspSession.h"
#include "esp/EspStatus.h"
#include "util/Log.h"

namespace esptool::esp {
namespace {

template <class T, std::size_t N>
void WriteIncludeQuery(FoIoConfigBlob& blob, CfgQuerySlot slot,
                       const T (&ids)[N]) noexcept {
  WriteU32At(blob.bytes, slot.include, kCfgIncludeEnabled);
  WriteU32At(blob.bytes, slot.count(), static_cast<std::uint32_t>(N));
  WritePtrAt(blob.bytes, slot.ptr(), ids);
}

template <class T, std::size_t N>
void WriteCountPtrQuery(FoIoConfigBlob& blob, std::size_t count_offset,
                        std::size_t ptr_offset, const T (&ids)[N]) noexcept {
  WriteU32At(blob.bytes, count_offset, static_cast<std::uint32_t>(N));
  WritePtrAt(blob.bytes, ptr_offset, ids);
}

void WriteFilterAt(FoIoConfigBlob& blob, std::size_t offset,
                   Filter filter) noexcept {
  if (filter) {
    WritePtrAt(blob.bytes, offset, filter);
  }
}

void BindConfigBlob(RuleDescriptor& descriptor, FoIoConfigBlob& blob) noexcept {
  WritePtrAt(&descriptor, kRuleEventConfigPtrOffset, blob.bytes);
}

void FillTypedIoQueries(FoIoConfigBlob& blob, const PropertyQueryStore& queries,
                        bool file_object_query, bool restrict_pipe,
                        bool mailslot_query) noexcept {
  WriteIncludeQuery(blob, kCfgThreadSlot, queries.thread_ids);
  WriteIncludeQuery(blob, kCfgProcessSlot, queries.process_ids);
  WriteU32At(blob.bytes, kCfgFileObjectIncludeOffset, kCfgIncludeEnabled);
  if (restrict_pipe) {
    WriteU32At(blob.bytes, kCfgFoTargetOffset, kFoTargetPipe);
  }
  if (file_object_query) {
    WriteIncludeQuery(blob, kCfgFileObjectSlot, queries.file_object_ids);
  }
  WriteIncludeQuery(blob, kCfgPipeSlot, queries.pipe_ids);
  if (mailslot_query) {
    WriteIncludeQuery(blob, kCfgMailslotSlot, queries.mailslot_ids);
  }
}

void AttachTypedIoConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                         const model::RuleSpec& spec, Filter filter,
                         const PropertyQueryStore& queries) {
  FillTypedIoQueries(blob, queries, IsFoIoEvent(spec.eventType),
                     RestrictPipeTarget(spec.eventType),
                     spec.eventType == kEventMailslotCreate);
  if (HasFileObjectLeaf(spec.filter) && IsFoIoEvent(spec.eventType)) {
    WriteFilterAt(blob, kFoIoFileObjectFilterOffset, filter);
  }
  BindConfigBlob(descriptor, blob);
}

void AttachRegistryConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                          Filter filter, const PropertyQueryStore& queries,
                          const std::int32_t* custom_ids = nullptr,
                          std::size_t custom_count = 0) {
  WriteFilterAt(blob, kRegistryConfigFilterOffset, filter);
  if (custom_ids != nullptr && custom_count > 0) {
    WriteU32At(blob.bytes, kRegistryConfigQueryCountOffset,
               static_cast<std::uint32_t>(custom_count));
    WritePtrAt(blob.bytes, kRegistryConfigQueryPtrOffset, custom_ids);
  } else {
    WriteCountPtrQuery(blob, kRegistryConfigQueryCountOffset,
                       kRegistryConfigQueryPtrOffset, queries.registry_ids);
  }
  BindConfigBlob(descriptor, blob);
}

void AttachThreadConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                        Filter filter, const PropertyQueryStore& queries,
                        const std::int32_t* custom_ids = nullptr,
                        std::size_t custom_count = 0) {
  WriteFilterAt(blob, kProcessConfigFilterOffset, filter);
  if (custom_ids != nullptr && custom_count > 0) {
    WriteU32At(blob.bytes, kProcessConfigQueryCountOffset,
               static_cast<std::uint32_t>(custom_count));
    WritePtrAt(blob.bytes, kProcessConfigQueryPtrOffset, custom_ids);
  } else {
    WriteCountPtrQuery(blob, kProcessConfigQueryCountOffset,
                       kProcessConfigQueryPtrOffset, queries.thread_ids);
  }
  BindConfigBlob(descriptor, blob);
}

void FillProcessConfigQueries(FoIoConfigBlob& blob, Filter filter,
                              const PropertyQueryStore& queries,
                              bool bind_child, bool write_queries = true,
                              const std::int32_t* custom_ids = nullptr,
                              std::size_t custom_count = 0) {
  WriteFilterAt(blob, kProcessConfigFilterOffset, filter);
  if (bind_child) {
    WriteU32At(blob.bytes, kProcessConfigBindingCountOffset, 1);
    WritePtrAt(blob.bytes, kProcessConfigBindingPtrOffset, &queries.child_bind);
  }
  if (write_queries) {
    if (custom_ids != nullptr && custom_count > 0) {
      WriteU32At(blob.bytes, kProcessConfigQueryCountOffset,
                 static_cast<std::uint32_t>(custom_count));
      WritePtrAt(blob.bytes, kProcessConfigQueryPtrOffset, custom_ids);
    } else {
      WriteCountPtrQuery(blob, kProcessConfigQueryCountOffset,
                         kProcessConfigQueryPtrOffset, queries.process_ids);
    }
  }
}

void AttachProcessCreateConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                               FoIoConfigBlob* child_blob, Filter filter,
                               Filter image_file_filter,
                               const PropertyQueryStore& queries,
                               const std::int32_t* custom_ids = nullptr,
                               std::size_t custom_count = 0) {
  const bool has_image_filter = static_cast<bool>(image_file_filter);
  const bool have_nested_child = filter && child_blob != nullptr;

  WriteFilterAt(blob, kProcessConfigFilterOffset, Filter{});
  if (has_image_filter) {
    WriteU32At(blob.bytes, kProcessConfigBindingCountOffset, 1);
    WritePtrAt(blob.bytes, kProcessConfigBindingPtrOffset, &queries.child_bind);
    WriteFilterAt(blob, kImageLoadFileObjectFilterOffset, image_file_filter);
  } else {
    WriteU32At(blob.bytes, kProcessConfigBindingCountOffset, 0);
    WritePtrAt(blob.bytes, kProcessConfigBindingPtrOffset, nullptr);
  }

  if (custom_ids != nullptr && custom_count > 0) {
    WriteU32At(blob.bytes, kProcessConfigQueryCountOffset,
               static_cast<std::uint32_t>(custom_count));
    WritePtrAt(blob.bytes, kProcessConfigQueryPtrOffset, custom_ids);
  } else {
    WriteCountPtrQuery(blob, kProcessConfigQueryCountOffset,
                       kProcessConfigQueryPtrOffset, queries.process_ids);
  }

  if (have_nested_child) {
    FillProcessConfigQueries(*child_blob, filter, queries, has_image_filter,
                             true, custom_ids, custom_count);
    void* child_ptr = child_blob->bytes;
    WritePtrAt(blob.bytes, kProcessConfigNestedOffset, child_ptr);
  }
  BindConfigBlob(descriptor, blob);
}

void AttachProcessConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                         Filter filter, const PropertyQueryStore& queries,
                         const std::int32_t* custom_ids = nullptr,
                         std::size_t custom_count = 0) {
  FillProcessConfigQueries(blob, filter, queries, false, true, custom_ids,
                           custom_count);
  BindConfigBlob(descriptor, blob);
}

void AttachImageLoadConfig(RuleDescriptor& descriptor, FoIoConfigBlob& blob,
                           Filter filter, bool file_object_leaf,
                           const PropertyQueryStore& queries,
                           const std::int32_t* custom_ids = nullptr,
                           std::size_t custom_count = 0) {
  const std::size_t offset = file_object_leaf ? kImageLoadFileObjectFilterOffset
                                              : kProcessConfigFilterOffset;
  WriteFilterAt(blob, offset, filter);
  if (custom_ids != nullptr && custom_count > 0) {
    WriteU32At(blob.bytes, kProcessConfigQueryCountOffset,
               static_cast<std::uint32_t>(custom_count));
    WritePtrAt(blob.bytes, kProcessConfigQueryPtrOffset, custom_ids);
  } else {
    WriteCountPtrQuery(blob, kProcessConfigQueryCountOffset,
                       kProcessConfigQueryPtrOffset, queries.process_ids);
  }
  BindConfigBlob(descriptor, blob);
}

void AttachDescriptorFilter(RuleDescriptor& descriptor,
                            const model::FilterNode& filter_node,
                            Filter filter) {
  const std::size_t filter_offset = FilterRuleOffset(filter_node);
  if (filter_offset != 0 &&
      filter_offset + sizeof(filter) <= sizeof(descriptor)) {
    WritePtrAt(&descriptor, filter_offset, filter);
  }
}

[[nodiscard]] std::uint32_t LifetimeToFfi(
    const model::RuleSpec& spec) noexcept {
  if (spec.lifetime == model::RuleLifetime::Persistent) {
    return kLifetimePersistFfi;
  }
  return kLifetimeTransientFfi;
}

// RuleActionMatchSubrules::new rejects a null a3 before it reads count 0.
alignas(8) const void* kEmptySubruleArray[1] = {};

}  // namespace

bool EspSession::IsEmptyFilter(const model::FilterNode& node) noexcept {
  return node.kind == model::FilterKind::Leaf && node.type == 0 &&
         node.children.empty();
}

std::uint32_t EspSession::ResolveActionSelector(std::uint64_t action) noexcept {
  return action != 0 ? static_cast<std::uint32_t>(action) : kActionQueueBacked;
}

bool EspSession::TryBuildRuleFilter(const model::RuleSpec& spec,
                                    Filter& filter) {
  filter.reset();
  if (IsEmptyFilter(spec.filter)) {
    return true;
  }
  const std::string label = spec.name.empty() ? spec.eventName : spec.name;
  const EspResult filter_result = CreateFilterTree(spec.filter, filter);
  Record(std::format("filter:{}", label), filter_result);
  if (Failed(filter_result)) {
    return false;
  }
  if (filter) {
    filters_.push_back(filter);
  }
  return true;
}

void EspSession::AttachFilterToDescriptor(RuleDescriptor& descriptor,
                                          const model::RuleSpec& spec,
                                          Filter filter) {
  if (IsThreadEventType(spec.eventType)) {
    const std::int32_t* custom_ids = nullptr;
    std::size_t custom_count = 0;
    for (const auto& recipe : spec.queries) {
      if (recipe.kind == "thread" && !recipe.properties.empty()) {
        std::vector<std::int32_t> custom;
        custom.reserve(recipe.properties.size() + 1);
        for (unsigned p : recipe.properties) {
          custom.push_back(static_cast<std::int32_t>(p));
        }
        if (std::ranges::find(custom, 1) == custom.end()) {
          custom.push_back(1);
        }
        dynamic_queries_.push_back(std::move(custom));
        custom_ids = dynamic_queries_.back().data();
        custom_count = dynamic_queries_.back().size();
        break;
      }
    }
    fo_io_configs_.emplace_back();
    AttachThreadConfig(descriptor, fo_io_configs_.back(), filter, query_store_,
                       custom_ids, custom_count);
    return;
  }
  if (NeedsTypedIoConfig(spec.eventType)) {
    fo_io_configs_.emplace_back();
    AttachTypedIoConfig(descriptor, fo_io_configs_.back(), spec, filter,
                        query_store_);
    if (HasProcessLeaf(spec.filter)) {
      AttachDescriptorFilter(descriptor, spec.filter, filter);
    }
    return;
  }
  if (NeedsProcessCreateConfig(spec.eventType)) {
    Filter image_file_filter;
    if (HasProcessLeaf(spec.filter)) {
      model::FilterNode fo = spec.filter;
      if (fo.kind == model::FilterKind::Leaf) {
        fo.type = kFilterCtorFileObject;
        if (fo.propertyId == 0) {
          fo.propertyId = 1;
        }
        const EspResult fo_result = CreateLeafFilter(fo, image_file_filter);
        Record("filter:child-image-fo", fo_result);
        if (Succeeded(fo_result) && image_file_filter) {
          filters_.push_back(image_file_filter);
        } else {
          image_file_filter.reset();
        }
      }
    }

    const std::int32_t* custom_ids = nullptr;
    std::size_t custom_count = 0;
    for (const auto& recipe : spec.queries) {
      if (recipe.kind == "process" && !recipe.properties.empty()) {
        std::vector<std::int32_t> custom;
        custom.reserve(recipe.properties.size() + 2);
        for (unsigned p : recipe.properties) {
          custom.push_back(static_cast<std::int32_t>(p));
        }
        if (std::ranges::find(custom, 6) == custom.end()) {
          custom.push_back(6);
        }
        if (std::ranges::find(custom, 20) == custom.end()) {
          custom.push_back(20);
        }
        dynamic_queries_.push_back(std::move(custom));
        custom_ids = dynamic_queries_.back().data();
        custom_count = dynamic_queries_.back().size();
        break;
      }
    }

    fo_io_configs_.emplace_back();
    AttachProcessCreateConfig(descriptor, fo_io_configs_.back(), nullptr,
                              Filter{}, image_file_filter, query_store_,
                              custom_ids, custom_count);
    return;
  }
  if (NeedsProcessConfig(spec.eventType)) {
    const std::int32_t* custom_ids = nullptr;
    std::size_t custom_count = 0;
    for (const auto& recipe : spec.queries) {
      if (recipe.kind == "process" && !recipe.properties.empty()) {
        std::vector<std::int32_t> custom;
        custom.reserve(recipe.properties.size() + 1);
        for (unsigned p : recipe.properties) {
          custom.push_back(static_cast<std::int32_t>(p));
        }
        if (std::ranges::find(custom, 6) == custom.end()) {
          custom.push_back(6);
        }
        dynamic_queries_.push_back(std::move(custom));
        custom_ids = dynamic_queries_.back().data();
        custom_count = dynamic_queries_.back().size();
        break;
      }
    }
    fo_io_configs_.emplace_back();
    AttachProcessConfig(descriptor, fo_io_configs_.back(), filter, query_store_,
                        custom_ids, custom_count);
    return;
  }
  if (NeedsImageLoadConfig(spec.eventType)) {
    const std::int32_t* custom_ids = nullptr;
    std::size_t custom_count = 0;
    for (const auto& recipe : spec.queries) {
      if (recipe.kind == "process" && !recipe.properties.empty()) {
        std::vector<std::int32_t> custom;
        custom.reserve(recipe.properties.size() + 1);
        for (unsigned p : recipe.properties) {
          custom.push_back(static_cast<std::int32_t>(p));
        }
        if (std::ranges::find(custom, 6) == custom.end()) {
          custom.push_back(6);
        }
        dynamic_queries_.push_back(std::move(custom));
        custom_ids = dynamic_queries_.back().data();
        custom_count = dynamic_queries_.back().size();
        break;
      }
    }
    fo_io_configs_.emplace_back();
    AttachImageLoadConfig(descriptor, fo_io_configs_.back(), filter,
                          HasFileObjectLeaf(spec.filter), query_store_,
                          custom_ids, custom_count);
    return;
  }
  if (IsRegistryEventType(spec.eventType)) {
    const std::int32_t* custom_ids = nullptr;
    std::size_t custom_count = 0;
    for (const auto& recipe : spec.queries) {
      if ((recipe.kind == "registry" || recipe.kind == "registry-key-object") &&
          !recipe.properties.empty()) {
        std::vector<std::int32_t> custom;
        custom.reserve(recipe.properties.size() + 1);
        for (unsigned p : recipe.properties) {
          custom.push_back(static_cast<std::int32_t>(p));
        }
        if (std::ranges::find(custom, 1) == custom.end()) {
          custom.push_back(1);
        }
        dynamic_queries_.push_back(std::move(custom));
        custom_ids = dynamic_queries_.back().data();
        custom_count = dynamic_queries_.back().size();
        break;
      }
    }
    fo_io_configs_.emplace_back();
    AttachRegistryConfig(descriptor, fo_io_configs_.back(), filter,
                         query_store_, custom_ids, custom_count);
    return;
  }
  if (filter) {
    AttachDescriptorFilter(descriptor, spec.filter, filter);
  }
}

bool EspSession::SubmitRuleBatch(const std::vector<RuleUpdateEntry>& entries) {
  const auto update_rules_fn = RequireTyped<UpdateRulesFn>("EspUpdateRules");
  if (update_rules_fn == nullptr) {
    return false;
  }
  const EspResult update_result =
      update_rules_fn(AsSharedWrapper(client_handle_), 0,
                      static_cast<unsigned>(entries.size()), entries.data());
  Record("EspUpdateRules", update_result);
  return Succeeded(update_result);
}

bool EspSession::EnsureEnforceCompatPatch() {
  if (enforce_compat_patch_attempted_) {
    return enforce_compat_patch_ok_;
  }
  enforce_compat_patch_attempted_ = true;
  std::string error;
  enforce_compat_patch_ok_ = ApplyFromFfiCompatPatch(&error);
  if (enforce_compat_patch_ok_) {
    enforce_compat_error_.clear();
  } else {
    enforce_compat_error_ = std::move(error);
  }
  Record("ApplyFromFfiCompatPatch", enforce_compat_patch_ok_ ? kOk : kFail);
  return enforce_compat_patch_ok_;
}

InstallStatus EspSession::InstallRules(const model::RuleDocument& document) {
  if (!client_handle_ || document.rules.empty()) {
    Warn("InstallRules requires a connected client and at least one rule");
    return InstallStatus::Failed;
  }
  bool needs_queue = false;
  for (const model::RuleSpec& spec : document.rules) {
    if (ResolvedActionNeedsQueue(spec.action, spec.actionName,
                                 spec.selector_override)) {
      needs_queue = true;
      break;
    }
  }
  if (needs_queue && !queue_handle_) {
    Warn("InstallRules requires a created queue for queue-backed rules");
    return InstallStatus::Failed;
  }
  const auto create_rule_fn = RequireTyped<CreateRuleFn>("EspCreateRule");
  if (create_rule_fn == nullptr ||
      RequireTyped<UpdateRulesFn>("EspUpdateRules") == nullptr) {
    return InstallStatus::Failed;
  }

  notify_queries_.clear();
  named_collections_.clear();
  if (!InstallDocumentCollections(document)) {
    Warn("InstallDocumentCollections failed");
    return InstallStatus::Failed;
  }
  for (const model::RuleSpec& spec : document.rules) {
    for (const model::QueryRecipe& recipe : spec.queries) {
      notify_queries_.emplace_back(spec.eventType, recipe);
    }
  }

  std::vector<RuleUpdateEntry> entries;
  entries.reserve(document.rules.size());
  // Parallel to `entries`. For a selector-7 (kActionMatchSubrules) entry this
  // is the predecessor handle its subrule array points at; nullptr for every
  // other entry. The per-entry submit loop below uses it to refuse an entry
  // whose anchor was rejected and closed.
  std::vector<void*> subrule_anchors;
  subrule_anchors.reserve(document.rules.size());
  const std::size_t rules_before = rules_.size();
  bool all_ok = true;
  for (const model::RuleSpec& spec : document.rules) {
    const std::string label = spec.name.empty() ? spec.eventName : spec.name;
    // Set when this rule's enforcing descriptor is built through the in-memory
    // espclient.dll compat patch rather than native client support.
    bool patched_install = false;
    void* subrule_anchor = nullptr;
    if (spec.eventType == 0) {
      Warn("rule has no event type: " + label);
      all_ok = false;
      continue;
    }

    Filter filter;
    if (!TryBuildRuleFilter(spec, filter)) {
      all_ok = false;
      continue;
    }

    // "deny" must resolve to the enforcing selector, never to the
    // notify-suppression selector: selector 4 is stored in the notify form and
    // cannot block (measured live on build 10.0.29641).
    const std::uint32_t named = ActionSelectorForName(
        spec.actionName, spec.action != 0
                             ? static_cast<std::uint32_t>(spec.action)
                             : kActionQueueBacked);
    if (!spec.actionName.empty() && spec.selector_override.has_value() &&
        *spec.selector_override != named) {
      // A selector override that disagrees with the named action would silently
      // downgrade a deny to a non-enforcing selector.
      Warn("rule '" + label + "': selector " +
           std::to_string(*spec.selector_override) +
           " conflicts with action \"" + spec.actionName + "\"");
      all_ok = false;
      continue;
    }
    const std::uint32_t selector = spec.selector_override.value_or(named);
    if (spec.actionName.empty() && selector == kActionNotifySuppress) {
      // Selector 4 was the historical "deny" spelling. It suppresses the queued
      // notification and never blocks, so the raw form is called out.
      Warn(
          "rule '" + label +
          "': selector 4 suppresses the queued notification and does not deny; "
          "use action=\"deny\" for enforcement");
    }
    RuleDescriptor descriptor{};
    descriptor.opaque16 = kRuleOrderKey;
    descriptor.lifetime = spec.modifier_override.value_or(LifetimeToFfi(spec));
    descriptor.flags = spec.flags;
    descriptor.event_type = spec.eventType;
    descriptor.action_selector = selector;
    if (selector == kActionRewrite) {
      const bool compat = IsEnforceCompatEventType(spec.eventType);
      std::uint32_t kind = EventModifyKindForEvent(spec.eventType);
      if (compat) {
        // The unpatched client's EventModify::from_ffi builds the enforcing
        // descriptor only for FoCreate (2000) and for 3007/8000/8001. The
        // --enforce-compat opt-in applies an in-memory patch so every
        // driver-ready type takes the FoCreate kind-3 path.
        if (!enforce_compat_) {
          Warn("rule '" + label + "': event type " +
               std::to_string(spec.eventType) +
               " needs the espclient.dll enforce-compat patch; re-run with "
               "--enforce-compat to install this deny rule");
          all_ok = false;
          continue;
        }
        if (!EnsureEnforceCompatPatch()) {
          Warn("rule '" + label +
               "': the enforce-compat patch is unavailable (" +
               enforce_compat_error_ + "); refusing the deny rule");
          all_ok = false;
          continue;
        }
        // The patched client routes every compat type through from_ffi's
        // FoCreate arm, which requires the kind-3 AccessMask descriptor.
        kind = kEventModifyKindFoCreate;
        patched_install = true;
      } else if (kind == 0) {
        // EspCreateRule rejects the enforcing selector with a zero event modify
        // kind (E_INVALIDARG). Refuse early with a named diagnostic instead of
        // installing a rule that cannot enforce.
        Warn("rule '" + label + "': event type " +
             std::to_string(spec.eventType) +
             " has no event modify kind; the enforcing action is unavailable "
             "for this event type");
        all_ok = false;
        continue;
      }
      if (!SupportsEnforcePayload(spec.eventType)) {
        // 3007, 8000, and 8001 have capability bit 0x02 clear, so the driver
        // cannot enforce them; 5000/6000 have the bit but no pre-operation DENY
        // callback, and 9000 has no capability record on this build. Refuse
        // early with a named diagnostic.
        Warn("rule '" + label +
             "': the enforcing action is unavailable for event type " +
             std::to_string(spec.eventType) +
             " (no enforce-capable driver bit or no DENY callback)");
        all_ok = false;
        continue;
      }
      std::uint32_t disposition_param =
          spec.modify_kind_override.value_or(kind);
      // +1112 low dword is the action disposition selector (1=virus, 2=access
      // denied, 3=not found). A leftover queue pointer here is tag 89. High
      // bits stay 0 so CreateRule does not treat it as a queue handle.
      descriptor.event_queue =
          std::bit_cast<void*>(static_cast<std::uintptr_t>(disposition_param));
      access_masks_.push_back(AccessMaskModification{});
      EventModifyBlob header{};
      header.count = 1;
      header.entries = &access_masks_.back();
      event_modify_blobs_.push_back(header);
      // +1088 is from_ffi kind (3 for 2000), not the AccessMask count.
      descriptor.event_modify_count = kind;
      descriptor.event_modify_size = kEventModifyAccessMaskBytes;
      descriptor.event_modify_ptr = &event_modify_blobs_.back();
    } else if (selector == kActionMatchSubrules) {
      const void* array = kEmptySubruleArray;
      std::uint32_t count = 0;
      if (!rules_.empty()) {
        void* const predecessor = rules_.back().abi();
        subrule_handles_.push_back(predecessor);
        // +1120 must point at this rule's own predecessor, not the vector head:
        // a second selector-7 rule in the same session would otherwise
        // reference the first predecessor's handle.
        array = &subrule_handles_.back();
        count = 1;
        // Anchor the entry to the predecessor it was built against. Every
        // descriptor is built before the first submit, so if that predecessor
        // is later rejected and closed the per-entry submit loop would arm this
        // rule over a dead handle. Record it so the loop can refuse this entry.
        if (rules_.size() > rules_before) {
          subrule_anchor = entries.back().rule;
        }
      }
      WriteU32At(&descriptor, kRuleSubruleCountOffset, count);
      WritePtrAt(&descriptor, kRuleSubruleArrayOffset, array);
    } else if (selector == kActionQueueBacked) {
      descriptor.event_queue = queue_handle_.abi();
    } else {
      descriptor.event_queue = nullptr;
    }
    // FoCreate rewrite still needs the FoIo config pointer at +96.
    // Leave FoIo +376 zero. EspRsSendUpdateRules copies that dword onto
    // the kernel message EventModify field; a non-zero stamp here is
    // rejected by EspCreateRule.
    AttachFilterToDescriptor(descriptor, spec, filter);

    void* raw = nullptr;
    const EspResult rule_result = create_rule_fn(&descriptor, &raw);
    Record(std::format("EspCreateRule:{}", label), rule_result);
    if (Failed(rule_result) || raw == nullptr) {
      all_ok = false;
      continue;
    }
    const Rule rule{raw};
    rules_.push_back(rule);
    RuleUpdateEntry entry{};
    entry.operation = kRuleUpdateOperationAdd;
    entry.rule = rule.abi();
    entries.push_back(entry);
    subrule_anchors.push_back(subrule_anchor);
    if (patched_install) {
      // Honest reporting: this rule is armed through an in-memory client patch,
      // not through native client support. A zero exit code must not be read as
      // proof that the rule denies.
      Log::Warn(
          std::format("enforce-compat: rule '{}' installed via in-memory "
                      "client patch; live "
                      "enforcement not verified",
                      label));
    }
  }

  if (entries.empty()) {
    return InstallStatus::Failed;
  }

  // Submit each rule individually. A single non-installable entry must not veto
  // its valid siblings: a mixed document (a compat deny entry next to a
  // driver-impossible one) still arms every entry the driver accepts. A whole
  // batch submit would drop the valid siblings when any one entry is rejected.
  // The handle for an entry the driver rejects is closed here so it is not left
  // orphaned in rules_ for the rest of the session.
  const auto close_fn = RequireTyped<CloseOutFn>("EspCloseRule");
  std::size_t committed = 0;
  std::size_t refused_at_submit = 0;
  // Handles the driver rejected and this loop closed. A selector-7 entry whose
  // subrule array anchors on one of them must not be submitted: the descriptor
  // captured that predecessor handle at build time and every descriptor is
  // built before the first submit, so the predecessor is already closed by the
  // time this entry is reached. The entry is treated as refused, so the install
  // status stays Partial and its own handle is closed with the rest.
  std::vector<void*> rejected_handles;
  for (std::size_t index = 0; index < entries.size(); ++index) {
    const bool anchor_rejected =
        subrule_anchors[index] != nullptr &&
        std::find(rejected_handles.begin(), rejected_handles.end(),
                  subrule_anchors[index]) != rejected_handles.end();
    if (!anchor_rejected && SubmitRuleBatch({entries[index]})) {
      ++committed;
      continue;
    }
    ++refused_at_submit;
    rejected_handles.push_back(entries[index].rule);
    Rule& handle = rules_[rules_before + index];
    if (handle && close_fn != nullptr) {
      close_fn(AsSharedWrapper(handle));
    }
    handle.reset();
  }
  // Compact out the handles the driver rejected so rules_ stays dense: later
  // subrule setup reads rules_.back() and the enumeration callers walk rules_,
  // and neither must see a null slot left by a refused submit.
  if (refused_at_submit != 0) {
    std::size_t write = rules_before;
    for (std::size_t read = rules_before; read < rules_.size(); ++read) {
      if (rules_[read]) {
        if (write != read) {
          rules_[write] = rules_[read];
        }
        ++write;
      }
    }
    rules_.resize(write);
  }

  if (committed == 0) {
    // Every created rule was rejected by the driver; nothing is armed.
    return InstallStatus::Failed;
  }
  // A refused entry or a submit rejection means the install is not complete, so
  // the caller can report the difference.
  return (all_ok && refused_at_submit == 0) ? InstallStatus::Complete
                                            : InstallStatus::Partial;
}

bool DocumentRequiresEnforceCompat(const model::RuleDocument& document) {
  for (const model::RuleSpec& spec : document.rules) {
    const std::uint32_t selector =
        spec.selector_override.value_or(ActionSelectorForName(
            spec.actionName, spec.action != 0
                                 ? static_cast<std::uint32_t>(spec.action)
                                 : kActionQueueBacked));
    if (selector == kActionRewrite &&
        IsEnforceCompatEventType(spec.eventType)) {
      return true;
    }
  }
  return false;
}

}  // namespace esptool::esp
