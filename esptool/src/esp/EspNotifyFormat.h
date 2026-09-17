#pragma once

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>

namespace esptool::esp {

struct DecodedProperty {
  std::string family;
  std::uint32_t id = 0;
  std::uint32_t type = 0;
  std::uint64_t raw_value = 0;
  std::string name;
  std::string formatted_value;
  bool is_string = false;
};

struct NotificationKeys {
  std::uint32_t event_type = 0;
  std::uint32_t pid = 0;
  std::uint32_t tid = 0;
  std::string name;
  std::vector<DecodedProperty> properties;
};

[[nodiscard]] std::string LookupPropertyName(std::string_view family,
                                             std::uint32_t property_id);

[[nodiscard]] bool DecodeNotificationKeys(const std::byte* bytes,
                                          NotificationKeys& out);
[[nodiscard]] std::string FormatEmptyNotificationLine(unsigned index);
[[nodiscard]] std::string FormatQueueNotification(const std::byte* bytes,
                                                  unsigned index);

}  // namespace esptool::esp
