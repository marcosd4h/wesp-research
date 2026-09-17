// In-memory removal of the espclient.dll client-side enforce gate. The patch
// and its inputs are documented in esp/EspEnforceCompat.h. The on-disk image is
// never modified; only this process's mapped copy of .text is rewritten.

#include "esp/EspEnforceCompat.h"

#include <Windows.h>
#include <bcrypt.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <format>
#include <string>
#include <vector>

#include "esp/EspCore.h"
#include "util/Log.h"
#include "util/StrHelpers.h"
#include "util/UniqueHandle.h"

#pragma comment(lib, "bcrypt.lib")

namespace esptool::esp {
namespace {

[[nodiscard]] bool ComputeFileSha256(const std::wstring& path,
                                     std::array<std::uint8_t, 32>& digest,
                                     std::string& error) {
  esptool::UniqueHandle file(
      CreateFileW(path.c_str(), GENERIC_READ,
                  FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
                  nullptr, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, nullptr));
  if (!file) {
    error = text::Win32Message("could not open espclient.dll for hashing",
                               GetLastError());
    return false;
  }

  BCRYPT_ALG_HANDLE algorithm = nullptr;
  BCRYPT_HASH_HANDLE hash = nullptr;
  std::vector<std::uint8_t> object;
  std::array<std::uint8_t, 4096> chunk{};

  const auto cleanup = [&]() {
    if (hash != nullptr) {
      BCryptDestroyHash(hash);
    }
    if (algorithm != nullptr) {
      BCryptCloseAlgorithmProvider(algorithm, 0);
    }
  };

  if (BCryptOpenAlgorithmProvider(&algorithm, BCRYPT_SHA256_ALGORITHM, nullptr,
                                  0) < 0) {
    error = "BCryptOpenAlgorithmProvider(SHA256) failed";
    return false;
  }

  DWORD object_size = 0;
  DWORD produced = 0;
  if (BCryptGetProperty(algorithm, BCRYPT_OBJECT_LENGTH,
                        reinterpret_cast<PUCHAR>(&object_size),
                        sizeof(object_size), &produced, 0) < 0) {
    cleanup();
    error = "BCryptGetProperty(BCRYPT_OBJECT_LENGTH) failed";
    return false;
  }
  object.assign(object_size, 0);
  if (BCryptCreateHash(algorithm, &hash, object.data(), object_size, nullptr, 0,
                       0) < 0) {
    cleanup();
    error = "BCryptCreateHash failed";
    return false;
  }

  for (;;) {
    DWORD read = 0;
    if (!ReadFile(file.get(), chunk.data(), static_cast<DWORD>(chunk.size()),
                  &read, nullptr)) {
      cleanup();
      error = text::Win32Message("could not read espclient.dll for hashing",
                                 GetLastError());
      return false;
    }
    if (read == 0) {
      break;
    }
    if (BCryptHashData(hash, chunk.data(), read, 0) < 0) {
      cleanup();
      error = "BCryptHashData failed";
      return false;
    }
  }

  const NTSTATUS finished = BCryptFinishHash(
      hash, digest.data(), static_cast<ULONG>(digest.size()), 0);
  cleanup();
  if (finished < 0) {
    error = "BCryptFinishHash failed";
    return false;
  }
  return true;
}

[[nodiscard]] bool ComputeModuleFileSha256(HMODULE module,
                                           std::array<std::uint8_t, 32>& digest,
                                           std::string& error) {
  std::wstring path(MAX_PATH, L'\0');
  for (;;) {
    const DWORD length = GetModuleFileNameW(module, path.data(),
                                            static_cast<DWORD>(path.size()));
    if (length == 0) {
      error = text::Win32Message("GetModuleFileNameW failed", GetLastError());
      return false;
    }
    if (static_cast<std::size_t>(length) < path.size()) {
      path.resize(length);
      break;
    }
    path.resize(path.size() * 2);
  }
  return ComputeFileSha256(path, digest, error);
}

struct ExecutableSection {
  std::uintptr_t rva = 0;
  std::size_t size = 0;
};

// Reads the mapped image's SizeOfImage and enumerates all executable section
// spans (IMAGE_SCN_MEM_EXECUTE) from its PE headers.
[[nodiscard]] bool ReadMappedImageSections(
    const void* module_base, std::uint32_t& image_size,
    std::vector<ExecutableSection>& exec_sections, std::string& error) {
  exec_sections.clear();
  const auto* base = static_cast<const std::uint8_t*>(module_base);
  IMAGE_DOS_HEADER dos{};
  std::memcpy(&dos, base, sizeof(dos));
  if (dos.e_magic != IMAGE_DOS_SIGNATURE) {
    error = "the mapped module has no DOS header (MZ signature)";
    return false;
  }
  const std::uint64_t nt_offset =
      static_cast<std::uint64_t>(static_cast<std::uint32_t>(dos.e_lfanew));
  constexpr std::uint64_t kMaxPeHeaderOffset = 0x10000000ull;  // 256 MiB
  if (nt_offset < sizeof(IMAGE_DOS_HEADER) || nt_offset > kMaxPeHeaderOffset) {
    error = "the mapped module's PE header offset is out of range";
    return false;
  }
  MEMORY_BASIC_INFORMATION region{};
  if (VirtualQuery(base, &region, sizeof(region)) == 0) {
    error = text::Win32Message("VirtualQuery on the mapped module failed",
                               GetLastError());
    return false;
  }
  const auto* const region_base =
      static_cast<const std::uint8_t*>(region.BaseAddress);
  const std::uint64_t offset_in_region =
      static_cast<std::uint64_t>(base - region_base);
  const std::uint64_t nt_read_end =
      offset_in_region + nt_offset + sizeof(IMAGE_NT_HEADERS64);
  if (nt_read_end > static_cast<std::uint64_t>(region.RegionSize)) {
    error = "the mapped module's PE header lies outside the committed region";
    return false;
  }
  IMAGE_NT_HEADERS64 nt{};
  std::memcpy(&nt, base + nt_offset, sizeof(nt));
  if (nt.Signature != IMAGE_NT_SIGNATURE) {
    error = "the mapped module has no PE header";
    return false;
  }
  if (nt.OptionalHeader.Magic != IMAGE_NT_OPTIONAL_HDR64_MAGIC) {
    error = "the mapped module is not a PE32+ image";
    return false;
  }
  image_size = nt.OptionalHeader.SizeOfImage;

  const std::uint16_t num_sections = nt.FileHeader.NumberOfSections;
  if (num_sections == 0) {
    exec_sections.push_back({0, image_size});
    return true;
  }

  const std::uint64_t sec_table_offset = nt_offset + sizeof(DWORD) +
                                         sizeof(IMAGE_FILE_HEADER) +
                                         nt.FileHeader.SizeOfOptionalHeader;
  const std::uint64_t sec_table_bytes =
      static_cast<std::uint64_t>(num_sections) * sizeof(IMAGE_SECTION_HEADER);
  if (offset_in_region + sec_table_offset + sec_table_bytes >
      static_cast<std::uint64_t>(region.RegionSize)) {
    error =
        "the mapped module's section headers lie outside the committed region";
    return false;
  }

  for (std::uint16_t i = 0; i < num_sections; ++i) {
    IMAGE_SECTION_HEADER sec{};
    std::memcpy(&sec,
                base + sec_table_offset + i * sizeof(IMAGE_SECTION_HEADER),
                sizeof(sec));
    if ((sec.Characteristics & IMAGE_SCN_MEM_EXECUTE) != 0) {
      const std::size_t sec_size =
          sec.Misc.VirtualSize != 0 ? sec.Misc.VirtualSize : sec.SizeOfRawData;
      if (sec.VirtualAddress < image_size && sec_size > 0) {
        exec_sections.push_back({sec.VirtualAddress, sec_size});
      }
    }
  }

  if (exec_sections.empty()) {
    exec_sections.push_back({0, image_size});
  }
  return true;
}

[[nodiscard]] bool ValidateCandidateSite(const std::uint8_t* candidate,
                                         const std::uint8_t* sec_start,
                                         const std::uint8_t* sec_end) noexcept {
  if (candidate < sec_start || candidate + kFromFfiPatchBytes + 2 > sec_end) {
    return false;
  }

  const bool is_original =
      std::memcmp(candidate, kFromFfiOriginalBytes, kFromFfiPatchBytes) == 0;
  const bool is_patched =
      std::memcmp(candidate, kFromFfiPatchedBytes, kFromFfiPatchBytes) == 0;
  if (!is_original && !is_patched) {
    return false;
  }

  const auto* next_inst = candidate + kFromFfiPatchBytes;
  bool has_je = false;
  std::size_t je_len = 0;
  if (next_inst[0] == 0x74) {
    has_je = true;
    je_len = 2;
  } else if (next_inst + 6 <= sec_end && next_inst[0] == 0x0F &&
             next_inst[1] == 0x84) {
    has_je = true;
    je_len = 6;
  }
  if (!has_je) {
    return false;
  }

  // Dual-anchor validation (AND requirement):
  // Anchor A: Preceding anchor (cmpl $0x1f3f, %edx / 7999: 81 FA 3F 1F 00 00)
  // Measured on 29641 & 29667: exactly at candidate - 8 bytes.
  const std::size_t lookback =
      std::min(static_cast<std::size_t>(candidate - sec_start),
               kFromFfiPrecedingMaxDistance);
  const auto* lookback_start = candidate - lookback;
  bool has_preceding_anchor = false;
  for (const auto* p = lookback_start;
       p + sizeof(kFromFfiPrecedingAnchor) <= candidate; ++p) {
    if (std::memcmp(p, kFromFfiPrecedingAnchor,
                    sizeof(kFromFfiPrecedingAnchor)) == 0) {
      has_preceding_anchor = true;
      break;
    }
  }
  if (!has_preceding_anchor) {
    return false;
  }

  // Anchor B: Following anchor (cmpl $0x0bbf, %edx / 3007: 81 FA BF 0B 00 00)
  // Measured on 29641 & 29667: exactly at candidate + 12 bytes (after near je).
  const auto* lookahead_start = next_inst + je_len;
  if (lookahead_start + sizeof(kFromFfiFollowingAnchor) > sec_end) {
    return false;
  }
  const std::size_t lookahead =
      std::min(static_cast<std::size_t>(sec_end - lookahead_start),
               kFromFfiFollowingMaxDistance);
  const auto* lookahead_end = lookahead_start + lookahead;
  bool has_following_anchor = false;
  for (const auto* p = lookahead_start;
       p + sizeof(kFromFfiFollowingAnchor) <= lookahead_end; ++p) {
    if (std::memcmp(p, kFromFfiFollowingAnchor,
                    sizeof(kFromFfiFollowingAnchor)) == 0) {
      has_following_anchor = true;
      break;
    }
  }
  return has_following_anchor;
}

}  // namespace

bool FindFromFfiPatchSite(const void* module_base, std::uintptr_t& out_rva,
                          std::string& error) {
  out_rva = 0;
  if (module_base == nullptr) {
    error = "module base is null";
    return false;
  }
  std::uint32_t image_size = 0;
  std::vector<ExecutableSection> exec_sections;
  if (!ReadMappedImageSections(module_base, image_size, exec_sections, error)) {
    return false;
  }

  const auto* base = static_cast<const std::uint8_t*>(module_base);
  std::vector<std::uintptr_t> matches;

  // 1. Check known candidate RVAs as search hints first
  for (std::uintptr_t hint_rva : kKnownCandidateRvas) {
    if (hint_rva + kFromFfiPatchBytes > image_size) {
      continue;
    }
    const auto* candidate = base + hint_rva;
    for (const auto& sec : exec_sections) {
      const auto* sec_start = base + sec.rva;
      const auto* sec_end = sec_start + sec.size;
      if (candidate >= sec_start && candidate + kFromFfiPatchBytes <= sec_end) {
        if (ValidateCandidateSite(candidate, sec_start, sec_end)) {
          matches.push_back(hint_rva);
        }
        break;
      }
    }
  }

  // If known RVAs did not match, or to ensure global uniqueness:
  if (matches.empty()) {
    for (const auto& sec : exec_sections) {
      const auto* sec_start = base + sec.rva;
      const auto* sec_end = sec_start + sec.size;
      if (sec.size < kFromFfiPatchBytes + 2) {
        continue;
      }
      for (const auto* p = sec_start; p + kFromFfiPatchBytes + 2 <= sec_end;
           ++p) {
        if (ValidateCandidateSite(p, sec_start, sec_end)) {
          const std::uintptr_t rva = static_cast<std::uintptr_t>(p - base);
          if (std::ranges::find(matches, rva) == matches.end()) {
            matches.push_back(rva);
          }
        }
      }
    }
  }

  if (matches.empty()) {
    error =
        "could not locate EventModify::from_ffi patch site in espclient.dll "
        "(signature not found or context anchors mismatched)";
    return false;
  }
  if (matches.size() > 1) {
    error = std::format(
        "ambiguous EventModify::from_ffi patch site in espclient.dll ({} "
        "matches "
        "found)",
        matches.size());
    return false;
  }

  out_rva = matches.front();
  return true;
}

bool ApplyFromFfiCompatPatchWithHooks(const CompatPatchHooks& hooks,
                                      std::string* error) {
  const auto fail = [&](std::string message) {
    if (error != nullptr) {
      *error = std::move(message);
    }
    return false;
  };

  if (hooks.module_base == nullptr || hooks.protect == nullptr) {
    return fail("the enforce-compat patch hooks are incomplete");
  }

  void* const module = hooks.module_base();
  if (module == nullptr) {
    return fail("espclient.dll is not loaded in this process");
  }

  // Diagnostic logging of module file SHA-256 (non-blocking)
  std::array<std::uint8_t, 32> digest{};
  std::string hash_error;
  if (hooks.file_sha256 != nullptr &&
      hooks.file_sha256(module, digest, hash_error)) {
    if (Log::WouldLog(LogLevel::Debug)) {
      std::string hex;
      hex.reserve(64);
      for (std::uint8_t b : digest) {
        hex += std::format("{:02x}", b);
      }
      Log::Debug(std::format("enforce-compat: espclient.dll sha256: {}", hex));
    }
  }

  // Dynamically locate the patch site using structural pattern matching
  std::uintptr_t patch_rva = 0;
  std::string locate_error;
  if (!FindFromFfiPatchSite(module, patch_rva, locate_error)) {
    return fail(locate_error);
  }

  auto* const target = static_cast<std::uint8_t*>(module) + patch_rva;
  std::array<std::uint8_t, kFromFfiPatchBytes> current{};
  std::memcpy(current.data(), target, current.size());

  if (std::equal(current.begin(), current.end(),
                 std::begin(kFromFfiPatchedBytes))) {
    if (Log::WouldLog(LogLevel::Info)) {
      Log::Info(std::format(
          "enforce-compat: EventModify::from_ffi already patched at RVA 0x{:X}",
          static_cast<std::uint64_t>(patch_rva)));
    }
    return true;  // Already patched: idempotent success.
  }
  if (!std::equal(current.begin(), current.end(),
                  std::begin(kFromFfiOriginalBytes))) {
    return fail(std::format(
        "espclient.dll EventModify::from_ffi bytes at RVA 0x{:X} match neither "
        "the original nor the patched pattern; refusing the enforce-compat "
        "patch",
        static_cast<std::uint64_t>(patch_rva)));
  }

  unsigned long original_protect = 0;
  if (!hooks.protect(target, current.size(), PAGE_EXECUTE_READWRITE,
                     &original_protect)) {
    return fail(text::Win32Message("VirtualProtect failed", GetLastError()));
  }
  std::memcpy(target, kFromFfiPatchedBytes, sizeof(kFromFfiPatchedBytes));
  FlushInstructionCache(GetCurrentProcess(), target,
                        sizeof(kFromFfiPatchedBytes));

  unsigned long ignored = 0;
  if (!hooks.protect(target, current.size(), original_protect, &ignored)) {
    // Revert bytes if restore fails
    std::memcpy(target, current.data(), current.size());
    FlushInstructionCache(GetCurrentProcess(), target, current.size());
    return fail(text::Win32Message(
        "VirtualProtect restore failed after the enforce-compat patch; the "
        "patch was reverted",
        GetLastError()));
  }

  if (Log::WouldLog(LogLevel::Info)) {
    Log::Info(std::format(
        "enforce-compat: EventModify::from_ffi successfully patched at RVA "
        "0x{:X}",
        static_cast<std::uint64_t>(patch_rva)));
  }
  return true;
}

CompatPatchHooks DefaultCompatPatchHooks() {
  CompatPatchHooks hooks;
  hooks.module_base = []() -> void* {
    return static_cast<void*>(GetModuleHandleW(kEspClientDll));
  };
  hooks.file_sha256 = [](void* module_base,
                         std::array<std::uint8_t, 32>& digest,
                         std::string& error) -> bool {
    return ComputeModuleFileSha256(static_cast<HMODULE>(module_base), digest,
                                   error);
  };
  hooks.protect = [](void* address, std::size_t size, unsigned long new_protect,
                     unsigned long* old_protect) -> bool {
    return VirtualProtect(address, size, new_protect, old_protect) != FALSE;
  };
  return hooks;
}

bool ApplyFromFfiCompatPatch(std::string* error) {
  return ApplyFromFfiCompatPatchWithHooks(DefaultCompatPatchHooks(), error);
}

bool ApplyEventTypeBypassPatch(std::string* error) {
  const auto fail = [&](std::string message) {
    if (error != nullptr) {
      *error = std::move(message);
    }
    return false;
  };
  const CompatPatchHooks hooks = DefaultCompatPatchHooks();
  void* const module = hooks.module_base();
  if (module == nullptr) {
    return fail("espclient.dll is not loaded in this process");
  }

  // The EspRsCreateRule event-type sparse-range validation is identical across
  // builds (only the RVA differs):
  //   lea r10d, [rax-1B58h]  ; 44 8D 90 A8 E4 FF FF  (r10d = event_type - 7000)
  //   cmp r10d, 0Fh          ; 41 83 FA 0F             (compare with 15)
  //   jb  short <accept>     ; 72 2A                    (accept when < 15)
  // Patch the `jb` (0x72) to an unconditional `jmp` (0xEB) so the 7015-7999
  // range is accepted and the kernel to_index OOB can be reached.
  constexpr std::array<std::uint8_t, 12> kPattern = {
      0x44, 0x8D, 0x90, 0xA8, 0xE4, 0xFF, 0xFF, 0x41, 0x83, 0xFA, 0x0F, 0x72};
  constexpr std::size_t kPatchIndex = 11;

  const auto* dos = static_cast<const IMAGE_DOS_HEADER*>(module);
  if (dos->e_magic != IMAGE_DOS_SIGNATURE) {
    return fail("espclient.dll has no valid DOS header");
  }
  const auto* nt = reinterpret_cast<const IMAGE_NT_HEADERS64*>(
      static_cast<const std::uint8_t*>(module) + dos->e_lfanew);
  if (nt->Signature != IMAGE_NT_SIGNATURE) {
    return fail("espclient.dll has no valid NT header");
  }
  const std::uint32_t image_size = nt->OptionalHeader.SizeOfImage;
  const auto* base = static_cast<const std::uint8_t*>(module);
  const auto* end = base + image_size - kPattern.size();

  const std::uint8_t* found = nullptr;
  for (const std::uint8_t* p = base; p <= end; ++p) {
    if (std::equal(kPattern.begin(), kPattern.end(), p)) {
      found = p;
      break;
    }
  }
  if (found == nullptr) {
    return fail(
        "could not locate the EspRsCreateRule event-type validation pattern "
        "in espclient.dll");
  }
  const std::uintptr_t rva =
      static_cast<std::uintptr_t>(found - base) + kPatchIndex;
  auto* const target = const_cast<std::uint8_t*>(found) + kPatchIndex;
  if (*target == 0xEB) {
    return true;  // Already patched: idempotent success.
  }

  unsigned long original_protect = 0;
  if (!hooks.protect(target, 1, PAGE_EXECUTE_READWRITE, &original_protect)) {
    return fail(text::Win32Message("VirtualProtect failed", GetLastError()));
  }
  *target = 0xEB;
  FlushInstructionCache(GetCurrentProcess(), target, 1);

  unsigned long ignored = 0;
  if (!hooks.protect(target, 1, original_protect, &ignored)) {
    *target = 0x72;
    FlushInstructionCache(GetCurrentProcess(), target, 1);
    return fail(text::Win32Message(
        "VirtualProtect restore failed after the event-type bypass patch; the "
        "patch was reverted",
        GetLastError()));
  }
  if (Log::WouldLog(LogLevel::Info)) {
    Log::Info(std::format(
        "event-type bypass: EspRsCreateRule patched at RVA 0x{:X}",
        static_cast<std::uint64_t>(rva)));
  }
  return true;
}

}  // namespace esptool::esp
