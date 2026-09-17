#include <doctest.h>

#include "esp/EspApi.h"
#include "esp/EspRefAbi.h"
#include "esp/EspSession.h"
#include "model/RuleDocument.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <string>
#include <string_view>
#include <vector>

using esptool::esp::Collection;
using esptool::esp::EspApi;
using esptool::esp::EspSession;
using esptool::esp::EventObject;
using esptool::esp::ExportDescriptor;
using esptool::esp::FileIdDescriptorRaw;
using esptool::esp::Guid;
using esptool::esp::InstallStatus;
using esptool::esp::IsNull;
using esptool::esp::ObjectReference;
using esptool::model::ClientSpec;
using esptool::model::CollectionSpec;
using esptool::model::RuleDocument;

// Host-only fail-closed coverage for EspSession against an UNLOADED EspApi
// (catalog present, every export address null). Do not LoadLibrary / EspApi::Load.
// Do not call PumpNotifications, PumpNotificationsIocp, IsEmptyFilter, or
// ResolveActionSelector — the first two wait; the last two are private.

namespace {

[[nodiscard]] bool HasWarning(const EspSession& session, std::string_view needle) {
  for (const std::string& warning : session.Warnings()) {
    if (warning.find(needle) != std::string::npos) {
      return true;
    }
  }
  return false;
}

}  // namespace

TEST_CASE("EspSession Connect fails closed on an unloaded catalog") {
  EspApi api;
  EspSession session(api);

  const ClientSpec spec{};
  CHECK_FALSE(session.Connect(spec));
  CHECK(HasWarning(session, "export not available"));
  CHECK_FALSE(session.ClientHandle());
  CHECK_FALSE(session.QueueHandle());
  CHECK_FALSE(session.NotificationHandle());
  CHECK(IsNull(session.ClientId()));
}

TEST_CASE("EspSession queue methods fail closed without a client") {
  EspApi api;
  EspSession session(api);

  CHECK_FALSE(session.CreateQueue());
  CHECK(HasWarning(session, "export not available"));
  CHECK_FALSE(session.OpenQueue(Guid{}));
  CHECK_FALSE(session.ConnectQueueToIocp(nullptr));
  CHECK_FALSE(session.ConnectQueueToCallback(nullptr, nullptr));
  CHECK_FALSE(session.ArmNotification());
  CHECK_FALSE(session.CompleteNotification());
  CHECK_FALSE(session.ClearQueue());
  session.CloseQueue();
}

TEST_CASE("EspSession InstallRules fails closed and warns") {
  EspApi api;
  EspSession session(api);

  const RuleDocument empty;
  CHECK(session.InstallRules(empty) == InstallStatus::Failed);
  CHECK(HasWarning(session,
                   "InstallRules requires a connected client and at least one rule"));
  CHECK_FALSE(session.ClientHandle());
  CHECK_FALSE(session.QueueHandle());
  CHECK_FALSE(session.NotificationHandle());
}

TEST_CASE("EspSession query methods fail closed") {
  EspApi api;
  EspSession session(api);

  CHECK_FALSE(session.QueryKind("event", EventObject{}, nullptr, 0));
  CHECK(HasWarning(session, "EspQueryEventProperties is not exported"));

  CHECK_FALSE(session.QueryKind("not-a-kind", EventObject{}, nullptr, 0));
  CHECK(HasWarning(session, "unknown query kind: "));
}

TEST_CASE("EspSession reference factories fail closed") {
  EspApi api;
  EspSession session(api);

  ObjectReference ref;
  Guid volume{};
  volume.data1 = 1;
  const FileIdDescriptorRaw file_id{};

  CHECK_FALSE(session.CreatePidReference("EspCreateProcessReference", 4, ref));
  CHECK_FALSE(session.CreatePathReference("EspCreateFileReferenceByPath",
                                         L"C:\\tmp", ref));
  CHECK_FALSE(session.CreateDesktopReference(L"Default", ref));
  CHECK_FALSE(session.CreateVolumeReference(volume, ref));
  CHECK_FALSE(session.CreateFileIdReference(volume, file_id, ref));
  CHECK_FALSE(session.CreateStreamByIdReference(volume, file_id, L":$DATA", ref));
  CHECK_FALSE(session.CreateEventObjectById(1, ref));
}

TEST_CASE("EspSession reference helpers fail closed") {
  EspApi api;
  EspSession session(api);

  const ObjectReference empty_ref;
  ObjectReference duplicate;
  EventObject view;
  std::uint64_t event_id = 0;
  int event_type = 0;

  CHECK_FALSE(session.UnwrapReference(empty_ref, view));
  CHECK_FALSE(session.DuplicateReference(empty_ref, duplicate));
  CHECK_FALSE(session.GetEventObjectId(view, event_id));
  CHECK_FALSE(session.GetEventObjectType(view, event_type));
  CHECK_FALSE(session.SetEventObjectContextKey(empty_ref));
  CHECK_FALSE(session.EnumerateEventObjectContextKeys(empty_ref));
  session.CloseReference(duplicate);
}

TEST_CASE("EspSession collection methods fail closed") {
  EspApi api;
  EspSession session(api);

  Collection opened;
  Guid collection_id{};
  collection_id.data1 = 1;
  CHECK_FALSE(session.OpenNamedCollection(collection_id, opened));

  int count = 0;
  std::vector<Guid> ids;
  CHECK_FALSE(session.EnumerateCollectionIds(1, count, &ids));

  const RuleDocument empty;
  CHECK(session.InstallDocumentCollections(empty));

  RuleDocument with_collection;
  with_collection.collections.push_back(CollectionSpec{});
  CHECK_FALSE(session.InstallDocumentCollections(with_collection));

  CHECK_FALSE(session.FindNamedCollection("missing"));
  CHECK_FALSE(session.ExerciseCollections());
  CHECK_FALSE(session.ExerciseCollectionsExtended(1, true, false, nullptr, 2));
  CHECK_FALSE(session.ExerciseContextKeys());
}

TEST_CASE("EspSession client and rule methods fail closed") {
  EspApi api;
  EspSession session(api);

  CHECK_FALSE(session.OpenQueueById(Guid{}));
  CHECK_FALSE(session.ConnectExisting(Guid{}));

  int count = 0;
  std::vector<Guid> ids;
  CHECK_FALSE(session.EnumerateClients(count, &ids));
  CHECK_FALSE(session.UnregisterClientId(Guid{}));
  CHECK_FALSE(session.EnumerateRuleIds(1, count));
  CHECK_FALSE(session.EnumerateAllRules(count));
  CHECK_FALSE(session.RemoveAllRules());
  CHECK_FALSE(session.RemoveRulesForLifetime(1));

  Guid queue_id{};
  CHECK_FALSE(session.GetQueueId(queue_id));
}

TEST_CASE("EspSession CreateIocpQueue does not leak a port") {
  EspApi api;
  EspSession session(api);

  HANDLE port = INVALID_HANDLE_VALUE;
  CHECK_FALSE(session.CreateIocpQueue(port));
  CHECK(port == INVALID_HANDLE_VALUE);
  CHECK(HasWarning(session, "export not available"));
}

TEST_CASE("EspSession CallRaw records an unresolved EspCreateRule invoke") {
  EspApi api;
  EspSession session(api);

  const ExportDescriptor* rule = api.Find("EspCreateRule");
  REQUIRE(rule != nullptr);
  CHECK(rule->address == nullptr);

  const std::array<std::uintptr_t, EspApi::kMaxArity> none{};
  CHECK(session.CallRaw(*rule, none) == 0);
  REQUIRE(session.Steps().size() == 1);
  CHECK(session.Steps()[0].step == "call:EspCreateRule");
  CHECK(session.Steps()[0].result == 0);
}

TEST_CASE("EspSession Disconnect is safe twice") {
  EspApi api;
  EspSession session(api);

  CHECK_FALSE(session.ClientHandle());
  const auto warn_count = session.Warnings().size();
  session.Disconnect();
  session.Disconnect();
  CHECK_FALSE(session.ClientHandle());
  CHECK_FALSE(session.QueueHandle());
  CHECK(session.Warnings().size() == warn_count);
}
