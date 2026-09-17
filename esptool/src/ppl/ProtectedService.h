#pragma once

#include <string>

namespace esptool::ppl {

// Creates a demand-start Win32 service that runs the supplied binary.
// CreateService only.
[[nodiscard]] bool Install(const std::wstring& service_name,
                           const std::wstring& binary_path,
                           const std::wstring& display_name, bool no_provision,
                           std::string& error);

// Stops and deletes a service created by Install.
[[nodiscard]] bool Uninstall(const std::wstring& service_name,
                             std::string& error);

// Connects to the service control manager and runs the service dispatcher.
// Returns 0 on success, the Win32 error otherwise.
[[nodiscard]] int RunService(const std::wstring& service_name, bool provision);

// Runs the service serve loop in the current process without the service
// control manager. Useful for debugging and for exercising the IPC path on a
// host where the service is not installed.
[[nodiscard]] int RunForeground(const std::wstring& pipe_name, bool provision);

}  // namespace esptool::ppl
