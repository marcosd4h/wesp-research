// Name table for this tool's 19 EspResult values. Unknown codes stringify
// as the word "HRESULT". Succeeded() is the sign bit only: kIoPending is
// Failed here; any pending-as-ok rewrite lives in the caller.

#include "esp/EspStatus.h"

#include <algorithm>
#include <array>
#include <format>
#include <ranges>

namespace esptool::esp {
namespace {

struct ResultName {
  EspResult value;
  const char* name;
};

constexpr auto kResultNames = std::to_array<ResultName>({
    {kOk, "S_OK"},
    {kFail, "E_FAIL"},
    {kAccessDenied, "E_ACCESSDENIED"},
    {kOutOfMemory, "E_OUTOFMEMORY"},
    {kInvalidArg, "E_INVALIDARG"},
    {kInsufficientBuffer, "ERROR_INSUFFICIENT_BUFFER"},
    {kModNotFound, "ERROR_MOD_NOT_FOUND"},
    {kAlreadyExists, "ERROR_ALREADY_EXISTS"},
    {kNoMoreItems, "ERROR_NO_MORE_ITEMS"},
    {kIoPending, "ERROR_IO_PENDING"},
    {kNotFound, "ERROR_NOT_FOUND"},
    {kTimeout, "ERROR_TIMEOUT"},
    {kInvalidState, "ERROR_INVALID_STATE"},
    {kStatusAccessDenied, "STATUS_ACCESS_DENIED"},
    {kStatusInvalidParameter, "STATUS_INVALID_PARAMETER"},
    {kStatusEntrypointNotFound, "STATUS_ENTRYPOINT_NOT_FOUND"},
    {kStatusAccessViolation, "STATUS_ACCESS_VIOLATION"},
    {kStatusStackBufferOverrun, "STATUS_STACK_BUFFER_OVERRUN"},
    {kStatusCancelled, "STATUS_CANCELLED"},
});

}  // namespace

std::string DescribeResult(EspResult result) {
  const auto found = std::ranges::find_if(
      kResultNames,
      [&](const ResultName& entry) { return entry.value == result; });
  return found == kResultNames.end() ? "HRESULT" : found->name;
}

std::string HexResult(EspResult result) {
  return std::format("0x{:08X}", static_cast<std::uint32_t>(result));
}

}  // namespace esptool::esp
