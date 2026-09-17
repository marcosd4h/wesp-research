#include <Windows.h>
#include <doctest.h>

#include <cstdint>
#include <string>
#include <vector>

#include "esp/EspEventIds.h"
#include "esp/EspMemoryView.h"
#include "esp/EspNotifyAbi.h"
#include "esp/EspNotifyFormat.h"

namespace {

[[nodiscard]] std::vector<std::byte> CommittedNotification(std::size_t bytes) {
  return std::vector<std::byte>(bytes);
}

}  // namespace

TEST_CASE("DecodeNotificationKeys rejects nullptr") {
  esptool::esp::NotificationKeys keys;
  CHECK_FALSE(esptool::esp::DecodeNotificationKeys(nullptr, keys));
}

TEST_CASE("DecodeNotificationKeys rejects an all-zero committed buffer") {
  auto buffer = CommittedNotification(1024);
  esptool::esp::NotificationKeys keys;
  CHECK_FALSE(esptool::esp::DecodeNotificationKeys(buffer.data(), keys));
  CHECK(keys.event_type == 0);
  CHECK(keys.pid == 0);
  CHECK(keys.name.empty());
}

TEST_CASE("DecodeNotificationKeys reads ProcessCreate type at +0xE0") {
  using esptool::esp::DecodeNotificationKeys;
  using esptool::esp::kEventDataTypeOffsetProcess;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::NotificationKeys;
  using esptool::esp::WriteU32At;

  auto buffer = CommittedNotification(1024);
  WriteU32At(buffer.data(), kEventDataTypeOffsetProcess, kEventProcessCreate);

  NotificationKeys keys;
  REQUIRE(DecodeNotificationKeys(buffer.data(), keys));
  CHECK(keys.event_type == kEventProcessCreate);
}

TEST_CASE("DecodeNotificationKeys reads query-slot pid") {
  using esptool::esp::DecodeNotificationKeys;
  using esptool::esp::kBoxedTypeU32;
  using esptool::esp::kEventDataTypeOffsetProcess;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kNotificationQueryCountOffset;
  using esptool::esp::kNotificationQueryPtrOffset;
  using esptool::esp::kProcessQueryPropertyPid;
  using esptool::esp::kQuerySlotPayloadOffset;
  using esptool::esp::kQuerySlotPropertyOffset;
  using esptool::esp::kQuerySlotTypeOffset;
  using esptool::esp::NotificationKeys;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;

  std::vector<std::byte> slot(16);
  WriteU32At(slot.data(), kQuerySlotPropertyOffset, kProcessQueryPropertyPid);
  WriteU32At(slot.data(), kQuerySlotTypeOffset, kBoxedTypeU32);
  WriteU32At(slot.data(), kQuerySlotPayloadOffset, 4242);

  auto buffer = CommittedNotification(1024);
  WriteU32At(buffer.data(), kEventDataTypeOffsetProcess, kEventProcessCreate);
  WriteU32At(buffer.data(), kNotificationQueryCountOffset, 1);
  WritePtrAt(buffer.data(), kNotificationQueryPtrOffset, slot.data());

  NotificationKeys keys;
  REQUIRE(DecodeNotificationKeys(buffer.data(), keys));
  CHECK(keys.event_type == kEventProcessCreate);
  CHECK(keys.pid == 4242);
}

TEST_CASE("FormatEmptyNotificationLine matches the zeroed field layout") {
  CHECK(esptool::esp::FormatEmptyNotificationLine(3) ==
        "notification 3 id=0 kind=0 payload=0 event=0 pid=0 tid=0 name=-");
}

TEST_CASE("FormatQueueNotification falls back when the buffer is unreadable") {
  using esptool::esp::FormatEmptyNotificationLine;
  using esptool::esp::FormatQueueNotification;

  CHECK(FormatQueueNotification(nullptr, 3) == FormatEmptyNotificationLine(3));

  void* no_access = VirtualAlloc(nullptr, 4096, MEM_COMMIT, PAGE_NOACCESS);
  REQUIRE(no_access != nullptr);
  const auto* unread = static_cast<const std::byte*>(no_access);
  CHECK(FormatQueueNotification(unread, 3) == FormatEmptyNotificationLine(3));
  CHECK(VirtualFree(no_access, 0, MEM_RELEASE));
}

TEST_CASE("FormatQueueNotification includes kind, id, payload, and event") {
  using esptool::esp::FormatQueueNotification;
  using esptool::esp::kEventDataTypeOffsetProcess;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kNotificationIdentifierOffset;
  using esptool::esp::kNotificationKindOffset;
  using esptool::esp::kNotificationPayloadLengthOffset;
  using esptool::esp::WriteBytesAt;
  using esptool::esp::WriteU32At;

  auto buffer = CommittedNotification(1024);
  WriteU32At(buffer.data(), kNotificationKindOffset, 11);
  WriteBytesAt(buffer.data(), kNotificationIdentifierOffset, std::uint64_t{99});
  WriteU32At(buffer.data(), kNotificationPayloadLengthOffset, 77);
  WriteU32At(buffer.data(), kEventDataTypeOffsetProcess, kEventProcessCreate);

  const std::string line = FormatQueueNotification(buffer.data(), 5);
  CHECK(line.find("notification 5") != std::string::npos);
  CHECK(line.find("id=99") != std::string::npos);
  CHECK(line.find("kind=11") != std::string::npos);
  CHECK(line.find("payload=77") != std::string::npos);
  CHECK(line.find("event=1000") != std::string::npos);
}

TEST_CASE("LookupPropertyName resolves friendly property names") {
  using esptool::esp::LookupPropertyName;

  CHECK(LookupPropertyName("Process", 6) == "ProcessId");
  CHECK(LookupPropertyName("Process", 20) == "ImagePath");
  CHECK(LookupPropertyName("Process", 1) == "CommandLine");
  CHECK(LookupPropertyName("Thread", 1) == "ThreadId");
  CHECK(LookupPropertyName("FileObject", 1) == "FileName");
  CHECK(LookupPropertyName("FileObject", 28) == "FileObjectType");
  CHECK(LookupPropertyName("Pipe", 1) == "PipeName");
  CHECK(LookupPropertyName("Mailslot", 1) == "MailslotName");
  CHECK(LookupPropertyName("Registry", 1) == "KeyPath");
  CHECK(LookupPropertyName("Unknown", 42) == "Prop_42");
}

TEST_CASE("FormatQueueNotification formats indented property detail lines") {
  using esptool::esp::DecodeNotificationKeys;
  using esptool::esp::FormatQueueNotification;
  using esptool::esp::kBoxedTypeInt32;
  using esptool::esp::kBoxedTypeUnicodeString;
  using esptool::esp::kEventDataTypeOffsetProcess;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kNotificationQueryCountOffset;
  using esptool::esp::kNotificationQueryPtrOffset;
  using esptool::esp::kQuerySlotPayloadOffset;
  using esptool::esp::kQuerySlotPropertyOffset;
  using esptool::esp::kQuerySlotTypeOffset;
  using esptool::esp::WritePtrAt;
  using esptool::esp::WriteU32At;

  // Build string descriptor for ImagePath
  const wchar_t path[] = L"C:\\Windows\\System32\\cmd.exe";
  std::vector<std::byte> string_desc(16);
  *reinterpret_cast<std::uint16_t*>(string_desc.data()) =
      static_cast<std::uint16_t>(wcslen(path) * sizeof(wchar_t));
  *reinterpret_cast<const wchar_t**>(string_desc.data() + 8) = path;

  std::vector<std::byte> slots(32);
  // Slot 0: ProcessId = 5123
  WriteU32At(slots.data(), 0, 6);
  WriteU32At(slots.data(), 4, kBoxedTypeInt32);
  *reinterpret_cast<std::uint64_t*>(slots.data() + 8) = 5123;
  // Slot 1: ImagePath = string_desc
  WriteU32At(slots.data(), 16, 20);
  WriteU32At(slots.data(), 20, kBoxedTypeUnicodeString);
  *reinterpret_cast<std::uint64_t*>(slots.data() + 24) =
      reinterpret_cast<std::uintptr_t>(string_desc.data());

  auto buffer = CommittedNotification(1024);
  WriteU32At(buffer.data(), kEventDataTypeOffsetProcess, kEventProcessCreate);
  WriteU32At(buffer.data(), kNotificationQueryCountOffset, 2);
  WritePtrAt(buffer.data(), kNotificationQueryPtrOffset, slots.data());

  esptool::esp::NotificationKeys keys;
  REQUIRE(DecodeNotificationKeys(buffer.data(), keys));
  CHECK(keys.pid == 5123);
  CHECK(keys.name == "C:\\Windows\\System32\\cmd.exe");
  REQUIRE(keys.properties.size() == 2);
  CHECK(keys.properties[0].id == 6);
  CHECK(keys.properties[0].family == "Process");
  CHECK(keys.properties[0].name == "ProcessId");
  CHECK(keys.properties[1].id == 20);
  CHECK(keys.properties[1].family == "Process");
  CHECK(keys.properties[1].name == "ImagePath");
  CHECK(keys.properties[1].formatted_value == "C:\\Windows\\System32\\cmd.exe");

  const std::string text = FormatQueueNotification(buffer.data(), 1);
  CHECK(text.find(
            "event=1000 pid=5123 tid=0 name=C:\\Windows\\System32\\cmd.exe") !=
        std::string::npos);
  CHECK(text.find("prop[Process:6] (ProcessId, type 5): 5123 (0x1403)") !=
        std::string::npos);
  CHECK(text.find("prop[Process:20] (ImagePath, type 8): "
                  "C:\\Windows\\System32\\cmd.exe") != std::string::npos);
}
