#pragma once

#include <cstdint>
#include <functional>
#include <string>
#include <vector>

#include "util/UniqueHandle.h"

namespace esptool::ipc {

// Request kinds exchanged between the standalone client and the service.
enum class RequestKind : std::uint32_t {
  Ping = 1,
  Status = 2,
  Exports = 3,
  Exercise = 4,
  Rules = 5,
};

// One framed request.
struct Request {
  RequestKind kind = RequestKind::Ping;
  std::string payload;
};

// One framed response.
struct Response {
  std::int32_t status = 0;
  std::string payload;
};

// Called by the server to produce the response for one decoded request.
using RequestHandler = std::function<void(const Request&, Response&)>;

// Framing helpers. Every message is a 32-bit length followed by a 32-bit kind
// or status and the payload, all little-endian. The transport is a byte-mode
// named pipe, so a read may return fewer bytes than requested and must be
// looped.
[[nodiscard]] std::vector<std::byte> Encode(const Request& request);
[[nodiscard]] std::vector<std::byte> Encode(const Response& response);

// Named-pipe server. Accepts one connection at a time and serves it until the
// client disconnects or Stop is called.
class PipeServer {
 public:
  PipeServer() = default;
  ~PipeServer();
  PipeServer(const PipeServer&) = delete;
  PipeServer& operator=(const PipeServer&) = delete;
  PipeServer(PipeServer&&) = delete;
  PipeServer& operator=(PipeServer&&) = delete;

  [[nodiscard]] bool Start(const std::wstring& pipe_name, std::string& error);
  void Stop();

  // Start() calls Stop(), stores pipe_name_, and creates the stop event.
  // It does not create the pipe. ServeOne opens one instance.
  // Returns false on bind/accept/stop; true after a wait that was not
  // stopped (including connect timeout with no session, and I/O failure
  // with error set).
  [[nodiscard]] bool ServeOne(const RequestHandler& handler,
                              std::string& error);

  [[nodiscard]] bool IsRunning() const noexcept { return !pipe_name_.empty(); }

 private:
  std::wstring pipe_name_;
  UniqueHandle stop_event_;
};

// Named-pipe client.
class PipeClient {
 public:
  PipeClient() = default;
  ~PipeClient();
  PipeClient(const PipeClient&) = delete;
  PipeClient& operator=(const PipeClient&) = delete;
  PipeClient(PipeClient&&) = delete;
  PipeClient& operator=(PipeClient&&) = delete;

  [[nodiscard]] bool Connect(const std::wstring& pipe_name, std::string& error);
  void Close();

  // Sends one request and waits for the response.
  [[nodiscard]] bool Exchange(const Request& request, Response& response,
                              std::string& error);

 private:
  UniqueHandle pipe_;
};

}  // namespace esptool::ipc
