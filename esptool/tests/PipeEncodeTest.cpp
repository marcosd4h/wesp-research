#include <doctest.h>
#include "ipc/PipeChannel.h"

#include <Windows.h>

#include <chrono>
#include <cstddef>
#include <cstdint>
#include <string>
#include <string_view>
#include <thread>
#include <vector>

using esptool::ipc::Encode;
using esptool::ipc::PipeClient;
using esptool::ipc::PipeServer;
using esptool::ipc::Request;
using esptool::ipc::RequestKind;
using esptool::ipc::Response;

namespace {

[[nodiscard]] std::uint32_t ReadLe32(const std::vector<std::byte>& frame,
                                     std::size_t offset) {
  return static_cast<std::uint32_t>(frame[offset]) |
         (static_cast<std::uint32_t>(frame[offset + 1]) << 8) |
         (static_cast<std::uint32_t>(frame[offset + 2]) << 16) |
         (static_cast<std::uint32_t>(frame[offset + 3]) << 24);
}

[[nodiscard]] bool Contains(const std::string& text, std::string_view needle) {
  return text.find(needle) != std::string::npos;
}

[[nodiscard]] bool ConnectWithRetry(PipeClient& client,
                                    const std::wstring& pipe_name,
                                    std::string& error) {
  for (int attempt = 0; attempt < 50; ++attempt) {
    error.clear();
    if (client.Connect(pipe_name, error)) {
      return true;
    }
    std::this_thread::sleep_for(std::chrono::milliseconds(10));
  }
  return false;
}

}  // namespace

TEST_CASE("Encode request Ping with payload hi is a 10-byte frame") {
  Request request;
  request.kind = RequestKind::Ping;
  request.payload = "hi";
  const std::vector<std::byte> frame = Encode(request);
  REQUIRE(frame.size() == 10);
  CHECK(ReadLe32(frame, 0) == 6u);
  CHECK(ReadLe32(frame, 4) == static_cast<std::uint32_t>(RequestKind::Ping));
  CHECK(frame[8] == std::byte{'h'});
  CHECK(frame[9] == std::byte{'i'});
}

TEST_CASE("Encode request with empty payload uses length dword 4") {
  Request request;
  request.kind = RequestKind::Status;
  request.payload.clear();
  const std::vector<std::byte> frame = Encode(request);
  REQUIRE(frame.size() == 8);
  CHECK(ReadLe32(frame, 0) == 4u);
  CHECK(ReadLe32(frame, 4) == static_cast<std::uint32_t>(RequestKind::Status));
}

TEST_CASE("Encode response with status 0 and payload ok") {
  Response response;
  response.status = 0;
  response.payload = "ok";
  const std::vector<std::byte> frame = Encode(response);
  REQUIRE(frame.size() == 10);
  CHECK(ReadLe32(frame, 0) == 6u);
  CHECK(ReadLe32(frame, 4) == 0u);
  CHECK(frame[8] == std::byte{'o'});
  CHECK(frame[9] == std::byte{'k'});
}

TEST_CASE("Encode response preserves a negative HRESULT-like status bit pattern") {
  Response response;
  response.status = static_cast<std::int32_t>(0x80004005u);
  response.payload.clear();
  const std::vector<std::byte> frame = Encode(response);
  REQUIRE(frame.size() == 8);
  CHECK(ReadLe32(frame, 0) == 4u);
  CHECK(ReadLe32(frame, 4) == 0x80004005u);
}

TEST_CASE("PipeServer Start then Stop toggles IsRunning") {
  PipeServer server;
  std::string error;
  const bool started = server.Start(L"esptool-ut-encode", error);
  CHECK(started);
  CHECK(server.IsRunning());
  server.Stop();
  CHECK_FALSE(server.IsRunning());
}

TEST_CASE("ServeOne without Start reports the server is not running") {
  PipeServer server;
  std::string error;
  const bool served = server.ServeOne({}, error);
  CHECK_FALSE(served);
  CHECK(Contains(error, "pipe server is not running"));
}

TEST_CASE("PipeClient Exchange without Connect reports the client is not connected") {
  PipeClient client;
  Request request;
  Response response;
  std::string error;
  const bool exchanged = client.Exchange(request, response, error);
  CHECK_FALSE(exchanged);
  CHECK(Contains(error, "pipe client is not connected"));
}

TEST_CASE("PipeClient Connect to a missing pipe fails with a nonempty error") {
  PipeClient client;
  std::string error;
  const bool connected = client.Connect(L"esptool-ut-missing-pipe", error);
  CHECK_FALSE(connected);
  CHECK(Contains(error, "could not open the service pipe"));
}

TEST_CASE("PipeClient Exchange receives a ping reply over a loopback pipe") {
  const std::wstring pipe_name =
      L"esptool-ut-loopback-" + std::to_wstring(GetCurrentProcessId());

  PipeServer server;
  std::string start_error;
  REQUIRE(server.Start(pipe_name, start_error));

  bool served = false;
  std::string serve_error;
  Request seen;
  seen.kind = RequestKind{};
  std::string seen_payload;
  std::thread server_thread([&] {
    served = server.ServeOne(
        [&](const Request& req, Response& reply) {
          seen = req;
          seen_payload = req.payload;
          reply.status = 0;
          reply.payload = "pong";
        },
        serve_error);
  });

  PipeClient client;
  std::string connect_error;
  const bool connected = ConnectWithRetry(client, pipe_name, connect_error);

  Response response;
  std::string exchange_error;
  bool exchanged = false;
  if (connected) {
    Request request;
    request.kind = RequestKind::Ping;
    request.payload = "ping";
    exchanged = client.Exchange(request, response, exchange_error);
  }

  server.Stop();
  server_thread.join();

  CHECK(connected);
  CHECK(exchanged);
  CHECK(served);
  CHECK(seen.kind == RequestKind::Ping);
  CHECK(seen_payload == "ping");
  CHECK(response.status == 0);
  CHECK(response.payload == "pong");
}

TEST_CASE("ServeOne after Stop does not invoke the handler") {
  PipeServer server;
  std::string start_error;
  REQUIRE(server.Start(L"esptool-ut-stopped", start_error));
  server.Stop();

  bool invoked = false;
  std::string error;
  const bool served = server.ServeOne(
      [&](const Request&, Response&) { invoked = true; }, error);
  CHECK_FALSE(served);
  CHECK_FALSE(invoked);
  CHECK(Contains(error, "pipe server is not running"));
}
