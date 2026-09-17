// SCM install/run/foreground. SC_HANDLE uses CloseServiceHandle; UniqueHandle
// is the wrong closer. Install is CreateService only.

#include "ppl/ProtectedService.h"

#include <Windows.h>
#include <winsvc.h>

#include <array>
#include <atomic>
#include <cstddef>
#include <format>
#include <string>
#include <thread>

#include "esp/EspApi.h"
#include "esp/EspExercise.h"
#include "esp/EspSession.h"
#include "esp/EspStatus.h"
#include "ipc/PipeChannel.h"
#include "model/RuleDocument.h"
#include "model/RuleParser.h"
#include "ppl/Protection.h"
#include "ppl/TokenAttribute.h"
#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueWin.h"

namespace esptool::ppl {
namespace {

constexpr DWORD kStopWaitHintMs = 3000;

std::wstring g_service_name;
SERVICE_STATUS_HANDLE g_status_handle = nullptr;
SERVICE_STATUS g_status{};
std::atomic<bool> g_stop_requested{false};
bool g_provision = true;

using text::Win32Message;

void ReportStatus(DWORD state, DWORD exit_code, DWORD wait_hint) {
  g_status.dwServiceType = SERVICE_WIN32_OWN_PROCESS;
  g_status.dwCurrentState = state;
  g_status.dwWin32ExitCode = exit_code;
  g_status.dwWaitHint = wait_hint;
  g_status.dwControlsAccepted =
      state == SERVICE_RUNNING ? SERVICE_ACCEPT_STOP : 0;
  if (g_status_handle != nullptr) {
    SetServiceStatus(g_status_handle, &g_status);
  }
}

void WINAPI ServiceControlHandler(DWORD control) {
  if (control == SERVICE_CONTROL_STOP) {
    g_stop_requested.store(true);
    ReportStatus(SERVICE_STOP_PENDING, NO_ERROR, kStopWaitHintMs);
  } else if (control == SERVICE_CONTROL_INTERROGATE) {
    ReportStatus(g_status.dwCurrentState, NO_ERROR, 0);
  }
}

void ServeLoop() {
  ipc::PipeServer server;
  std::string error;
  if (!server.Start(g_service_name, error)) {
    Log::Error(std::format("could not create the service pipe: {}", error));
    return;
  }

  std::string trust_error;
  if (!RequireSystemWithTcb(trust_error)) {
    Log::Error(trust_error);
    return;
  }
  if (g_provision) {
    const unsigned permission = QueryCurrentProcess().IsAntimalwareLight()
                                    ? kWespPermissionFull
                                    : kWespPermissionRestricted;
    std::string attribute_error;
    if (!SetWespPermission(permission, attribute_error)) {
      Log::Warn(std::format("could not set {}: {}", kWespPermissionClaim,
                            attribute_error));
    } else {
      Log::Info(std::format("{} set to {}", kWespPermissionClaim, permission));
    }
  }

  esp::EspApi api;
  if (!api.Load()) {
    Log::Error(std::format("espclient.dll could not be loaded: {}",
                           api.LastErrorMessage()));
  }

  esp::EspSession session(api);
  std::atomic<bool> connected{false};
  std::thread connect_thread;
  // Connect runs on a background thread. The pipe loop starts before it
  // finishes.
  if (api.IsLoaded()) {
    connect_thread = std::thread([&api, &session, &connected]() {
      model::ClientSpec client;
      client.name = "esptool-service";
      connected.store(session.Connect(client));
      if (!connected.load()) {
        Log::Warn("client registration failed; the service keeps serving");
      }
    });
  }

  Log::Info(std::format("esptool service is listening on pipe '{}'",
                        text::ToUtf8(g_service_name)));
  const ipc::RequestHandler handler = [&api, &session, &connected](
                                          const ipc::Request& request,
                                          ipc::Response& response) {
    response.status = 0;
    switch (request.kind) {
      case ipc::RequestKind::Ping:
        response.payload = "pong";
        break;
      case ipc::RequestKind::Status: {
        TokenAttributeState attribute;
        std::string attribute_error;
        const bool have_attribute =
            QueryWespPermission(attribute, attribute_error);
        (void)have_attribute;
        // Hardcoded. Not the result of an account or TCB query.
        response.payload = std::format(
            "{}\naccount=SYSTEM tcb=enabled\nattribute={}\nconnect={}",
            QueryCurrentProcess().Describe(), attribute.Describe(),
            connected.load() ? "ok" : "pending_or_failed");
        break;
      }
      case ipc::RequestKind::Exports:
        response.payload = std::format("resolved {} of {}", api.ResolvedCount(),
                                       api.ExportCount());
        break;
      case ipc::RequestKind::Exercise: {
        esp::EspExercise exercise(api, session);
        const std::vector<esp::ExportOutcome> outcomes =
            exercise.RunInProcess();
        std::size_t succeeded = 0;
        for (const esp::ExportOutcome& outcome : outcomes) {
          if (outcome.invoked &&
              esp::Succeeded(static_cast<esp::EspResult>(outcome.result))) {
            ++succeeded;
          }
        }
        response.payload = std::format("exercised {}, succeeded {}",
                                       outcomes.size(), succeeded);
        break;
      }
      case ipc::RequestKind::Rules: {
        const model::ParseOutcome parsed =
            model::ParseRuleText(request.payload);
        if (!parsed.ok) {
          response.status = esp::kInvalidArg;
          response.payload = std::format("parse error: {}", parsed.error);
          break;
        }
        // The service host cannot arm an enforce-compat deny rule. The
        // in-memory espclient.dll patch is opt-in per process via
        // --enforce-compat, and the IPC Rules request carries no such flag, so
        // the host never calls SetEnforceCompat(true). A deny rule whose event
        // type needs the patch would be refused by InstallRules and the target
        // operation would still complete. Refuse the whole document with a
        // named diagnostic instead of letting the caller read "parsed N rules,
        // install succeeded" as a working denial. Arm those documents with the
        // standalone `rules --enforce-compat` client, not over IPC.
        if (esp::DocumentRequiresEnforceCompat(parsed.document)) {
          Log::Error(
              "ipc rules: the document contains an enforcing rule for an event "
              "type that needs the espclient.dll enforce-compat patch; the "
              "service host does not enable --enforce-compat, so the rule "
              "cannot be armed from here");
          response.status = esp::kInvalidArg;
          response.payload =
              "enforce-compat is unavailable from the service host; use the "
              "standalone rules --enforce-compat client";
          break;
        }
        const esp::InstallStatus installed = session.InstallRules(parsed.document);
        response.payload = std::format(
            "parsed {} rules, install {}", parsed.document.rules.size(),
            installed == esp::InstallStatus::Complete
                ? "succeeded"
                : (installed == esp::InstallStatus::Partial ? "partial"
                                                            : "failed"));
        if (installed != esp::InstallStatus::Complete) {
          response.status = esp::kFail;
        }
        break;
      }
    }
  };
  while (!g_stop_requested.load()) {
    std::string serve_error;
    if (!server.ServeOne(handler, serve_error)) {
      if (!g_stop_requested.load() && !serve_error.empty()) {
        Log::Error(std::format("pipe server stopped: {}", serve_error));
      }
      break;
    }
  }

  server.Stop();
  if (connect_thread.joinable()) {
    connect_thread.join();
  }
  session.Disconnect();
  api.Unload();
  Log::Info("esptool service stopped");
}

void WINAPI ServiceMain(DWORD, LPWSTR*) {
  g_status_handle = RegisterServiceCtrlHandlerW(g_service_name.c_str(),
                                                ServiceControlHandler);
  if (g_status_handle == nullptr) {
    Log::Error(std::format("RegisterServiceCtrlHandler failed (error {})",
                           GetLastError()));
    return;
  }
  ReportStatus(SERVICE_RUNNING, NO_ERROR, 0);
  try {
    ServeLoop();
  } catch (...) {
    Log::Error("the service loop raised an unexpected exception");
  }
  ReportStatus(SERVICE_STOPPED, NO_ERROR, 0);
}

}  // namespace

bool Install(const std::wstring& service_name, const std::wstring& binary_path,
             const std::wstring& display_name, bool no_provision,
             std::string& error) {
  error.clear();
  // CreateService only.
  UniqueServiceHandle manager(
      OpenSCManagerW(nullptr, nullptr, SC_MANAGER_ALL_ACCESS));
  if (!manager) {
    error = Win32Message("OpenSCManager failed", GetLastError());
    return false;
  }
  // The SCM starts the image with no arguments, so the registered command
  // line must re-enter the tool in service mode.
  std::wstring command_line = L"\"" + binary_path + L"\" service run --log \"" +
                              binary_path + L".log\"";
  if (no_provision) {
    command_line += L" --no-provision";
  }
  UniqueServiceHandle service(CreateServiceW(
      manager.get(), service_name.c_str(), display_name.c_str(),
      SERVICE_ALL_ACCESS, SERVICE_WIN32_OWN_PROCESS, SERVICE_DEMAND_START,
      SERVICE_ERROR_NORMAL, command_line.c_str(), nullptr, nullptr, nullptr,
      nullptr, nullptr));
  if (!service) {
    const DWORD failure = GetLastError();
    if (failure == ERROR_SERVICE_EXISTS) {
      error =
          std::format("service already exists: {}", text::ToUtf8(service_name));
    } else {
      error = Win32Message("CreateService failed", failure);
    }
    return false;
  }
  return true;
}

bool Uninstall(const std::wstring& service_name, std::string& error) {
  error.clear();

  ScmService scm;
  if (!OpenScmService(service_name, SC_MANAGER_CONNECT,
                      SERVICE_STOP | SERVICE_QUERY_STATUS | DELETE, scm,
                      error)) {
    return false;
  }

  SERVICE_STATUS status{};
  ControlService(scm.service.get(), SERVICE_CONTROL_STOP, &status);

  const BOOL deleted = DeleteService(scm.service.get());
  const DWORD delete_error = deleted ? ERROR_SUCCESS : GetLastError();

  if (!deleted) {
    error = Win32Message("DeleteService failed", delete_error);
    return false;
  }
  error.clear();
  return true;
}

int RunForeground(const std::wstring& pipe_name, bool provision) {
  if (pipe_name.empty()) {
    return static_cast<int>(ERROR_INVALID_PARAMETER);
  }
  g_service_name = pipe_name;
  g_provision = provision;
  g_stop_requested.store(false);
  Log::Info("esptool foreground service starting");
  ServeLoop();
  Log::Info("esptool foreground service stopped");
  return 0;
}

int RunService(const std::wstring& service_name, bool provision) {
  if (service_name.empty()) {
    return static_cast<int>(ERROR_INVALID_PARAMETER);
  }
  g_service_name = service_name;
  g_provision = provision;
  g_stop_requested.store(false);
  g_status_handle = nullptr;

  std::array<SERVICE_TABLE_ENTRYW, 2> table{};
  table[0].lpServiceName = g_service_name.data();
  table[0].lpServiceProc = &ServiceMain;
  if (!StartServiceCtrlDispatcherW(table.data())) {
    return static_cast<int>(GetLastError());
  }
  return 0;
}

}  // namespace esptool::ppl
