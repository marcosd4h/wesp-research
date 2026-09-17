#include "ipc/PipeChannel.h"

#include <Windows.h>

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <string_view>

#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

namespace esptool::ipc {
namespace {

constexpr DWORD kPipeBufferSize = 64 * 1024;
constexpr DWORD kConnectTimeoutMs = 60000;
constexpr DWORD kIoTimeoutMs = 15000;
constexpr std::size_t kFrameTagBytes = sizeof(std::uint32_t);
constexpr DWORD kBusyWaitMs = 1000;
constexpr int kConnectAttempts = 5;
constexpr wchar_t kLocalPipePrefix[] = L"\\\\.\\pipe\\";

void AppendUint32(std::vector<std::byte>& out, std::uint32_t value) {
  for (int shift = 0; shift < 32; shift += 8) {
    out.push_back(static_cast<std::byte>((value >> shift) & 0xFFu));
  }
}

[[nodiscard]] std::optional<std::uint32_t> ReadUint32(
    std::span<const std::byte>& remaining) noexcept {
  constexpr std::size_t kBytes = sizeof(std::uint32_t);
  if (remaining.size() < kBytes) {
    return std::nullopt;
  }
  std::uint32_t value = 0;
  for (std::size_t index = 0; index < kBytes; ++index) {
    value |= static_cast<std::uint32_t>(remaining[index]) << (index * 8);
  }
  remaining = remaining.subspan(kBytes);
  return value;
}

using text::Win32Message;

template <typename StartIo>
[[nodiscard]] bool TransferOverlapped(HANDLE pipe, bool reading,
                                      StartIo&& start, DWORD& transferred,
                                      std::string& error) {
  OVERLAPPED overlapped{};
  UniqueHandle event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  overlapped.hEvent = event.get();
  if (!event) {
    error = Win32Message("CreateEvent failed", GetLastError());
    return false;
  }
  transferred = 0;
  const BOOL started = start(overlapped, transferred);
  if (started) {
    return true;
  }
  const DWORD pending = GetLastError();
  if (pending != ERROR_IO_PENDING) {
    error = Win32Message(reading ? "pipe read failed" : "pipe write failed",
                         pending);
    return false;
  }
  const DWORD wait = WaitForSingleObject(overlapped.hEvent, kIoTimeoutMs);
  if (wait == WAIT_OBJECT_0) {
    if (GetOverlappedResult(pipe, &overlapped, &transferred, FALSE)) {
      return true;
    }
    error = Win32Message(reading ? "pipe read failed" : "pipe write failed",
                         GetLastError());
    return false;
  }
  if (wait == WAIT_TIMEOUT) {
    CancelIoEx(pipe, &overlapped);
    error = reading ? "pipe read timed out" : "pipe write timed out";
    return false;
  }
  error = Win32Message("pipe wait failed", GetLastError());
  return false;
}

[[nodiscard]] bool TransferRead(HANDLE pipe, std::span<std::byte> buffer,
                                DWORD& transferred, std::string& error) {
  const DWORD size = static_cast<DWORD>(buffer.size());
  return TransferOverlapped(
      pipe, true,
      [&](OVERLAPPED& overlapped, DWORD& done) {
        return ReadFile(pipe, buffer.data(), size, &done, &overlapped);
      },
      transferred, error);
}

[[nodiscard]] bool TransferWrite(HANDLE pipe, std::span<const std::byte> buffer,
                                 DWORD& transferred, std::string& error) {
  const DWORD size = static_cast<DWORD>(buffer.size());
  return TransferOverlapped(
      pipe, false,
      [&](OVERLAPPED& overlapped, DWORD& done) {
        return WriteFile(pipe, buffer.data(), size, &done, &overlapped);
      },
      transferred, error);
}

[[nodiscard]] bool ReadExactly(HANDLE pipe, std::span<std::byte> buffer,
                               std::string& error) {
  auto remaining = buffer;
  while (!remaining.empty()) {
    DWORD transferred = 0;
    if (!TransferRead(pipe, remaining, transferred, error)) {
      return false;
    }
    if (transferred == 0) {
      error = "the pipe connection closed";
      return false;
    }
    remaining = remaining.subspan(transferred);
  }
  return true;
}

[[nodiscard]] bool WriteExactly(HANDLE pipe, std::span<const std::byte> buffer,
                                std::string& error) {
  auto remaining = buffer;
  while (!remaining.empty()) {
    DWORD transferred = 0;
    if (!TransferWrite(pipe, remaining, transferred, error)) {
      return false;
    }
    if (transferred == 0) {
      error = "the pipe connection closed while writing";
      return false;
    }
    remaining = remaining.subspan(transferred);
  }
  return true;
}

// Length is kind/status + payload (payload.size()+kFrameTagBytes). It does
// not include the length dword.
[[nodiscard]] std::vector<std::byte> EncodeFrame(std::uint32_t tag,
                                                 std::string_view payload) {
  std::vector<std::byte> frame;
  frame.reserve(payload.size() + kFrameTagBytes + sizeof(std::uint32_t));
  AppendUint32(frame,
               static_cast<std::uint32_t>(payload.size() + kFrameTagBytes));
  AppendUint32(frame, tag);
  const auto bytes = std::as_bytes(std::span(payload.data(), payload.size()));
  frame.insert(frame.end(), bytes.begin(), bytes.end());
  return frame;
}

[[nodiscard]] bool DecodeFrame(std::span<const std::byte> body,
                               std::uint32_t& tag, std::string& payload) {
  auto remaining = body;
  const std::optional<std::uint32_t> parsed = ReadUint32(remaining);
  if (!parsed) {
    return false;
  }
  tag = *parsed;
  payload.assign(reinterpret_cast<const char*>(remaining.data()),
                 remaining.size());
  return true;
}

}  // namespace

std::vector<std::byte> Encode(const Request& request) {
  return EncodeFrame(static_cast<std::uint32_t>(request.kind), request.payload);
}

std::vector<std::byte> Encode(const Response& response) {
  return EncodeFrame(response.status, response.payload);
}

PipeServer::~PipeServer() { Stop(); }

bool PipeServer::Start(const std::wstring& pipe_name, std::string& error) {
  Stop();
  pipe_name_ = pipe_name;
  stop_event_.reset(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  if (!stop_event_) {
    error = Win32Message("CreateEvent failed", GetLastError());
    pipe_name_.clear();
    return false;
  }
  return true;
}

void PipeServer::Stop() {
  if (stop_event_) {
    SetEvent(stop_event_.get());
    stop_event_.reset();
  }
  pipe_name_.clear();
}

bool PipeServer::ServeOne(const RequestHandler& handler, std::string& error) {
  error.clear();
  if (pipe_name_.empty() || !stop_event_) {
    error = "pipe server is not running";
    return false;
  }
  const std::wstring full_name = kLocalPipePrefix + pipe_name_;
  UniqueHandle pipe(CreateNamedPipeW(
      full_name.c_str(), PIPE_ACCESS_DUPLEX | FILE_FLAG_OVERLAPPED,
      PIPE_TYPE_BYTE | PIPE_READMODE_BYTE | PIPE_WAIT, PIPE_UNLIMITED_INSTANCES,
      kPipeBufferSize, kPipeBufferSize, kConnectTimeoutMs, nullptr));
  if (!pipe) {
    error = Win32Message("CreateNamedPipe failed", GetLastError());
    return false;
  }

  OVERLAPPED connect{};
  UniqueHandle connect_event(CreateEventW(nullptr, TRUE, FALSE, nullptr));
  connect.hEvent = connect_event.get();
  if (!connect_event) {
    error = Win32Message("CreateEvent failed", GetLastError());
    return false;
  }
  const BOOL connecting = ConnectNamedPipe(pipe.get(), &connect);
  const DWORD connect_error = connecting ? ERROR_SUCCESS : GetLastError();
  bool stopped = false;
  if (!connecting && connect_error == ERROR_IO_PENDING) {
    const std::array<HANDLE, 2> waits{stop_event_.get(), connect.hEvent};
    const DWORD wait =
        WaitForMultipleObjects(static_cast<DWORD>(waits.size()), waits.data(),
                               FALSE, kConnectTimeoutMs);
    if (wait == WAIT_OBJECT_0) {
      CancelIoEx(pipe.get(), &connect);
      stopped = true;
    } else if (wait == WAIT_TIMEOUT) {
      CancelIoEx(pipe.get(), &connect);
    }
  } else if (!connecting && connect_error != ERROR_PIPE_CONNECTED) {
    error = Win32Message("ConnectNamedPipe failed", connect_error);
    return false;
  }
  if (stopped) {
    return false;
  }

  std::uint32_t length = 0;
  if (ReadExactly(pipe.get(), std::as_writable_bytes(std::span{&length, 1}),
                  error)) {
    if (length < kFrameTagBytes || length > kPipeBufferSize) {
      error = "invalid request frame length";
    } else {
      std::vector<std::byte> body(length);
      if (ReadExactly(pipe.get(), std::span<std::byte>(body), error)) {
        Request request;
        Response response;
        std::uint32_t kind = 0;
        if (!DecodeFrame(body, kind, request.payload)) {
          error = "truncated request frame";
        } else {
          request.kind = static_cast<RequestKind>(kind);
          if (handler) {
            handler(request, response);
          }
          const std::vector<std::byte> frame = Encode(response);
          if (!WriteExactly(pipe.get(), std::span<const std::byte>(frame),
                            error) &&
              error.empty()) {
            error = "the response could not be written";
          }
        }
      }
    }
  }

  FlushFileBuffers(pipe.get());
  DisconnectNamedPipe(pipe.get());
  return true;
}

PipeClient::~PipeClient() { Close(); }

bool PipeClient::Connect(const std::wstring& pipe_name, std::string& error) {
  Close();
  const std::wstring full_name = kLocalPipePrefix + pipe_name;
  for (int attempt = 0; attempt < kConnectAttempts; ++attempt) {
    pipe_.reset(CreateFileW(full_name.c_str(), GENERIC_READ | GENERIC_WRITE, 0,
                            nullptr, OPEN_EXISTING, FILE_FLAG_OVERLAPPED,
                            nullptr));
    if (pipe_) {
      return true;
    }
    const DWORD failure = GetLastError();
    if (failure != ERROR_PIPE_BUSY) {
      error = Win32Message("could not open the service pipe", failure);
      return false;
    }
    WaitNamedPipeW(full_name.c_str(), kBusyWaitMs);
  }
  error = "the service pipe is busy";
  return false;
}

void PipeClient::Close() { pipe_.reset(); }

bool PipeClient::Exchange(const Request& request, Response& response,
                          std::string& error) {
  if (!pipe_) {
    error = "pipe client is not connected";
    return false;
  }
  const std::vector<std::byte> frame = Encode(request);
  if (!WriteExactly(pipe_.get(), std::span<const std::byte>(frame), error)) {
    return false;
  }
  std::uint32_t length = 0;
  if (!ReadExactly(pipe_.get(), std::as_writable_bytes(std::span{&length, 1}),
                   error)) {
    return false;
  }
  if (length < kFrameTagBytes || length > kPipeBufferSize) {
    error = "invalid response frame length";
    return false;
  }
  std::vector<std::byte> body(length);
  if (!ReadExactly(pipe_.get(), std::span<std::byte>(body), error)) {
    return false;
  }
  std::uint32_t status = 0;
  if (!DecodeFrame(body, status, response.payload)) {
    error = "truncated response frame";
    return false;
  }
  response.status = static_cast<std::int32_t>(status);
  return true;
}

}  // namespace esptool::ipc
