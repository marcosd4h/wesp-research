#include <Windows.h>
#include <doctest.h>

#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <string>
#include <vector>

#include "esp/EspEnforceCompat.h"
#include "esp/EspEventConfigAbi.h"
#include "esp/EspEventIds.h"
#include "esp/EspRuleAbi.h"

TEST_CASE(
    "IsEnforceCompatEventType accepts the corrected driver-ready deny set") {
  using esptool::esp::IsEnforceCompatEventType;
  using esptool::esp::kEventFoOpen;
  using esptool::esp::kEventFoRead;
  using esptool::esp::kEventFoWrite;
  using esptool::esp::kEventFsMin;
  using esptool::esp::kEventProcessCreate;
  using esptool::esp::kEventVolumeFsctl;
  using esptool::esp::kEventVolumeMount;

  CHECK(IsEnforceCompatEventType(kEventProcessCreate));
  CHECK(IsEnforceCompatEventType(kEventFoOpen));
  CHECK(IsEnforceCompatEventType(kEventFoRead));
  CHECK(IsEnforceCompatEventType(kEventFoWrite));

  // Filesystem family 3000 through 3008, minus FileQueryOpen (3007).
  CHECK(IsEnforceCompatEventType(kEventFsMin));
  for (std::uint32_t type = 3000; type <= 3008; ++type) {
    CHECK(IsEnforceCompatEventType(type) == (type != 3007));
  }

  CHECK(IsEnforceCompatEventType(kEventVolumeMount));
  CHECK(IsEnforceCompatEventType(kEventVolumeFsctl));
}

TEST_CASE("IsEnforceCompatEventType rejects excluded and non-driver types") {
  using esptool::esp::IsEnforceCompatEventType;

  // FoCreate already works without the compat patch.
  CHECK_FALSE(IsEnforceCompatEventType(2000));
  // FoCleanup: capability mask 0x09 (bit 0x02 clear) and no FoCleanup
  // disposition, so it fails both conditions.
  CHECK_FALSE(IsEnforceCompatEventType(2004));
  // Object-manager pair: capability record 0x19 has bit 0x02 clear.
  CHECK_FALSE(IsEnforceCompatEventType(8000));
  CHECK_FALSE(IsEnforceCompatEventType(8001));
  // FileQueryOpen is inside the capability range 3000..3008 but its class has
  // no FS disposition, so the second condition excludes it.
  CHECK_FALSE(IsEnforceCompatEventType(3007));
  // 5000/6000 have bit 0x02 set but no pre-operation DENY callback; 9000 has no
  // capability record on this build.
  CHECK_FALSE(IsEnforceCompatEventType(5000));
  CHECK_FALSE(IsEnforceCompatEventType(6000));
  CHECK_FALSE(IsEnforceCompatEventType(9000));
  // Registry is driver-accepted but the class cannot block (no create/open
  // disposition) and 7003 cannot even build an enforcing descriptor.
  for (std::uint32_t type = 7000; type <= 7014; ++type) {
    CHECK_FALSE(IsEnforceCompatEventType(type));
  }
  CHECK_FALSE(IsEnforceCompatEventType(7000));
  CHECK_FALSE(IsEnforceCompatEventType(7003));
  // Other capability-clear types and gaps.
  CHECK_FALSE(IsEnforceCompatEventType(0));
  CHECK_FALSE(IsEnforceCompatEventType(1));
  CHECK_FALSE(IsEnforceCompatEventType(3));
  CHECK_FALSE(IsEnforceCompatEventType(1001));
  CHECK_FALSE(IsEnforceCompatEventType(1002));
  CHECK_FALSE(IsEnforceCompatEventType(3009));
  CHECK_FALSE(IsEnforceCompatEventType(3010));
  CHECK_FALSE(IsEnforceCompatEventType(3011));
  CHECK_FALSE(IsEnforceCompatEventType(4001));
  CHECK_FALSE(IsEnforceCompatEventType(7015));
  CHECK_FALSE(IsEnforceCompatEventType(1999));
  CHECK_FALSE(IsEnforceCompatEventType(41234));
}

TEST_CASE(
    "driver capability mask matches the wesp.sys Event Capability Bitmask") {
  using esptool::esp::DriverEventCapabilityMask;

  // mask 0x03 -> 1000, 2001
  CHECK(DriverEventCapabilityMask(1000) == 0x03);
  CHECK(DriverEventCapabilityMask(2001) == 0x03);
  // mask 0x1B -> 2000, 7000, 7001
  CHECK(DriverEventCapabilityMask(2000) == 0x1B);
  CHECK(DriverEventCapabilityMask(7000) == 0x1B);
  CHECK(DriverEventCapabilityMask(7001) == 0x1B);
  // mask 0x0B -> 2002, 2003, 3000..3008, 4000, 4002, 5000, 6000, 7002..7014
  CHECK(DriverEventCapabilityMask(2002) == 0x0B);
  CHECK(DriverEventCapabilityMask(2003) == 0x0B);
  for (std::uint32_t type = 3000; type <= 3008; ++type) {
    CAPTURE(type);
    CHECK(DriverEventCapabilityMask(type) == 0x0B);
  }
  CHECK(DriverEventCapabilityMask(4000) == 0x0B);
  CHECK(DriverEventCapabilityMask(4002) == 0x0B);
  CHECK(DriverEventCapabilityMask(5000) == 0x0B);
  CHECK(DriverEventCapabilityMask(6000) == 0x0B);
  for (std::uint32_t type = 7002; type <= 7014; ++type) {
    CAPTURE(type);
    CHECK(DriverEventCapabilityMask(type) == 0x0B);
  }
  // mask 0x09 (bit 0x02 CLEAR) -> 2004, 3009
  CHECK(DriverEventCapabilityMask(2004) == 0x09);
  CHECK(DriverEventCapabilityMask(3009) == 0x09);
  // mask 0x19 (bit 0x02 CLEAR) -> the object-manager pair. Live-recorded:
  // ObCreateHandle reads `40 1f 00 00 19 00 00 00`, so the pair has a real
  // record whose enforce-capable bit is clear.
  CHECK(DriverEventCapabilityMask(8000) == 0x19);
  CHECK(DriverEventCapabilityMask(8001) == 0x19);
  // No capability record on this build.
  CHECK(DriverEventCapabilityMask(3010) == 0);
  CHECK(DriverEventCapabilityMask(3011) == 0);
  CHECK(DriverEventCapabilityMask(4001) == 0);
  CHECK(DriverEventCapabilityMask(9000) == 0);
  CHECK(DriverEventCapabilityMask(0) == 0);
}

TEST_CASE(
    "every accepted compat type is enforce-capable and writes a disposition") {
  using esptool::esp::DriverEventCapabilityMask;
  using esptool::esp::IsDispositionWritingCallback;
  using esptool::esp::IsEnforceCompatEventType;
  using esptool::esp::kDriverEnforceCapableBit;

  // Sweep the whole event-type domain. Every type accepted by
  // IsEnforceCompatEventType must (a) have a capability mask with bit 0x02 set
  // and (b) be a disposition-writing callback. A new type added to the
  // disposition set without a mask entry gets mask 0 and fails this sweep, so
  // the manual-enumeration error (2004) cannot recur.
  std::size_t accepted = 0;
  for (std::uint32_t type = 0; type <= 10000; ++type) {
    if (!IsEnforceCompatEventType(type)) {
      continue;
    }
    ++accepted;
    CAPTURE(type);
    CHECK(IsDispositionWritingCallback(type));
    const std::uint32_t mask = DriverEventCapabilityMask(type);
    CHECK(mask != 0);
    CHECK((mask & kDriverEnforceCapableBit) != 0);
  }
  // 1000, 2001, 2002, 2003, 3000-3006, 3008, 4000, 4002.
  CHECK(accepted == 14);
}

TEST_CASE("enforce-compat descriptor fields are kind 3 and size 16") {
  using esptool::esp::AccessMaskModification;
  using esptool::esp::EnforceModifyKindForEvent;
  using esptool::esp::EventModifyBlob;
  using esptool::esp::kEventModifyAccessMaskBytes;
  using esptool::esp::kEventModifyKindFoCreate;
  using esptool::esp::RuleDescriptor;

  CHECK(kEventModifyKindFoCreate == 3);
  CHECK(kEventModifyAccessMaskBytes == 16);
  CHECK(sizeof(AccessMaskModification) == 8);
  CHECK(sizeof(EventModifyBlob) == 16);
  CHECK(offsetof(RuleDescriptor, event_modify_count) == 1088);
  CHECK(offsetof(RuleDescriptor, event_modify_size) == 1092);
  CHECK(offsetof(RuleDescriptor, event_modify_ptr) == 1096);

  // FoCreate and every compat type share the kind-3 AccessMask descriptor.
  for (const std::uint32_t type :
       {2000u, 1000u, 2001u, 2002u, 2003u, 3000u, 3008u, 4000u, 4002u}) {
    CHECK(EnforceModifyKindForEvent(type) == kEventModifyKindFoCreate);
  }
  // FoCleanup is no longer a compat type, so it falls back to the natural
  // mapping (0: no event modify kind).
  CHECK(EnforceModifyKindForEvent(2004) == 0);
  // The driver-impossible types keep their historical non-enforce kinds.
  CHECK(EnforceModifyKindForEvent(3007) == 4);
  CHECK(EnforceModifyKindForEvent(8000) == 1);
  CHECK(EnforceModifyKindForEvent(8001) == 2);
  // Registry is no longer in the compat set, so it falls back to the natural
  // mapping (0: no event modify kind).
  CHECK(EnforceModifyKindForEvent(7000) == 0);
  CHECK(EnforceModifyKindForEvent(7003) == 0);
}

TEST_CASE("SupportsEnforcePayload is true for FoCreate and the compat set") {
  using esptool::esp::SupportsEnforcePayload;

  CHECK(SupportsEnforcePayload(2000));
  CHECK(SupportsEnforcePayload(1000));
  CHECK(SupportsEnforcePayload(2001));
  CHECK(SupportsEnforcePayload(2003));
  CHECK(SupportsEnforcePayload(3008));
  CHECK(SupportsEnforcePayload(4000));
  CHECK_FALSE(SupportsEnforcePayload(3007));
  CHECK_FALSE(SupportsEnforcePayload(8000));
  CHECK_FALSE(SupportsEnforcePayload(8001));
  CHECK_FALSE(SupportsEnforcePayload(5000));
  CHECK_FALSE(SupportsEnforcePayload(6000));
  CHECK_FALSE(SupportsEnforcePayload(9000));
  // Registry cannot block and 7003 cannot build; both are excluded.
  CHECK_FALSE(SupportsEnforcePayload(7000));
  CHECK_FALSE(SupportsEnforcePayload(7003));
}

TEST_CASE("from_ffi compat patch constants are well formed") {
  using esptool::esp::kFromFfiEventTypeCheckRva;
  using esptool::esp::kFromFfiOriginalBytes;
  using esptool::esp::kFromFfiPatchBytes;
  using esptool::esp::kFromFfiPatchedBytes;
  using esptool::esp::kFromFfiRva;

  CHECK(kFromFfiEventTypeCheckRva > kFromFfiRva);
  CHECK(kFromFfiPatchBytes == 6);
  CHECK(kFromFfiOriginalBytes[0] == 0x81);
  CHECK(kFromFfiOriginalBytes[1] == 0xFA);
  CHECK(kFromFfiPatchedBytes[0] == 0x39);
  CHECK(kFromFfiPatchedBytes[1] == 0xD2);
  CHECK(kFromFfiPatchedBytes[2] == 0x90);

  bool identical = true;
  for (std::size_t index = 0; index < kFromFfiPatchBytes; ++index) {
    identical = identical &&
                (kFromFfiOriginalBytes[index] == kFromFfiPatchedBytes[index]);
  }
  CHECK_FALSE(identical);
}

// ---------------------------------------------------------------------------
// Injectable-seam fail-closed coverage for ApplyFromFfiCompatPatchWithHooks.
// The fake image carries real PE headers so the bounds check is exercised, and
// the hooks substitute the module base, the on-disk hash, and page protection.
// ---------------------------------------------------------------------------
namespace {

using esptool::esp::ApplyFromFfiCompatPatchWithHooks;
using esptool::esp::CompatPatchHooks;
using esptool::esp::kEnforceCompatExpectedSha256;
using esptool::esp::kFromFfiEventTypeCheckRva;
using esptool::esp::kFromFfiOriginalBytes;
using esptool::esp::kFromFfiPatchBytes;
using esptool::esp::kFromFfiPatchedBytes;

constexpr std::size_t kFakeNtOffset = 0x80;
constexpr std::size_t kFakeImageSize = 0x70000;

struct FakeImage {
  std::vector<std::uint8_t> bytes;
  std::uintptr_t current_rva = kFromFfiEventTypeCheckRva;

  FakeImage() : bytes(kFakeImageSize, 0) {
    auto* dos = reinterpret_cast<IMAGE_DOS_HEADER*>(bytes.data());
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = static_cast<LONG>(kFakeNtOffset);
    auto* nt =
        reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + kFakeNtOffset);
    nt->Signature = IMAGE_NT_SIGNATURE;
    nt->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nt->FileHeader.NumberOfSections = 1;
    nt->FileHeader.SizeOfOptionalHeader =
        static_cast<WORD>(sizeof(IMAGE_OPTIONAL_HEADER64));
    nt->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nt->OptionalHeader.SizeOfImage = static_cast<DWORD>(kFakeImageSize);

    auto* sec = IMAGE_FIRST_SECTION(nt);
    std::memcpy(sec->Name, ".text", 5);
    sec->VirtualAddress = 0x1000;
    sec->Misc.VirtualSize = static_cast<DWORD>(kFakeImageSize - 0x1000);
    sec->Characteristics =
        IMAGE_SCN_CNT_CODE | IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_MEM_READ;

    SetupSiteAt(kFromFfiEventTypeCheckRva);
  }

  void SetupSiteAt(std::uintptr_t rva, bool patched = false) {
    if (current_rva >= 8 && current_rva + 24 <= bytes.size()) {
      std::memset(bytes.data() + current_rva - 8, 0, 32);
    }
    current_rva = rva;
    // Preceding anchor at rva - 8: 81 FA 3F 1F 00 00 7F 6A
    std::memcpy(bytes.data() + rva - 8, esptool::esp::kFromFfiPrecedingAnchor,
                sizeof(esptool::esp::kFromFfiPrecedingAnchor));
    bytes[rva - 2] = 0x7F;  // jg
    bytes[rva - 1] = 0x6A;

    // Site bytes
    std::memcpy(bytes.data() + rva,
                patched ? esptool::esp::kFromFfiPatchedBytes
                        : esptool::esp::kFromFfiOriginalBytes,
                esptool::esp::kFromFfiPatchBytes);

    // Following near je: 0F 84 F8 00 00 00
    bytes[rva + 6] = 0x0F;
    bytes[rva + 7] = 0x84;
    bytes[rva + 8] = 0xF8;
    bytes[rva + 9] = 0x00;
    bytes[rva + 10] = 0x00;
    bytes[rva + 11] = 0x00;

    // Following anchor at rva + 12: 81 FA BF 0B 00 00
    std::memcpy(bytes.data() + rva + 12, esptool::esp::kFromFfiFollowingAnchor,
                sizeof(esptool::esp::kFromFfiFollowingAnchor));
  }

  [[nodiscard]] std::uint8_t* base() noexcept { return bytes.data(); }

  [[nodiscard]] const std::uint8_t* site() const noexcept {
    return bytes.data() + current_rva;
  }

  void SetSizeOfImage(std::uint32_t value) noexcept {
    auto* nt =
        reinterpret_cast<IMAGE_NT_HEADERS64*>(bytes.data() + kFakeNtOffset);
    nt->OptionalHeader.SizeOfImage = value;
  }

  void SetSiteBytes(
      const std::uint8_t (&value)[esptool::esp::kFromFfiPatchBytes]) {
    std::memcpy(bytes.data() + current_rva, value,
                esptool::esp::kFromFfiPatchBytes);
  }

  [[nodiscard]] bool SiteMatches(const std::uint8_t (
      &value)[esptool::esp::kFromFfiPatchBytes]) const noexcept {
    return std::memcmp(site(), value, esptool::esp::kFromFfiPatchBytes) == 0;
  }
};

constexpr std::uint8_t kUnknownSiteBytes[kFromFfiPatchBytes] = {
    0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC};

FakeImage* g_image = nullptr;
std::array<std::uint8_t, 32> g_digest = {};
bool g_hash_ok = true;
int g_protect_calls = 0;
int g_fail_protect_on_call = 0;

void* TestModuleBase() {
  return g_image != nullptr ? g_image->base() : nullptr;
}

bool TestFileSha256(void*, std::array<std::uint8_t, 32>& digest, std::string&) {
  digest = g_digest;
  return g_hash_ok;
}

bool TestProtect(void*, std::size_t, unsigned long,
                 unsigned long* old_protect) {
  ++g_protect_calls;
  if (old_protect != nullptr) {
    *old_protect = PAGE_EXECUTE_READ;
  }
  if (g_fail_protect_on_call != 0 &&
      g_protect_calls == g_fail_protect_on_call) {
    return false;
  }
  return true;
}

[[nodiscard]] CompatPatchHooks TestHooks() {
  CompatPatchHooks hooks;
  hooks.module_base = &TestModuleBase;
  hooks.file_sha256 = &TestFileSha256;
  hooks.protect = &TestProtect;
  return hooks;
}

void ResetTestHooks() {
  g_image = nullptr;
  std::memcpy(g_digest.data(), kEnforceCompatExpectedSha256, g_digest.size());
  g_hash_ok = true;
  g_protect_calls = 0;
  g_fail_protect_on_call = 0;
}

}  // namespace

TEST_CASE("from_ffi compat patch applies and is idempotent through the seam") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;

  std::string error;
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
  const int protect_calls_after_patch = g_protect_calls;
  CHECK(protect_calls_after_patch == 2);

  // Already-patched bytes short-circuit before any protect call.
  error.clear();
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(g_protect_calls == protect_calls_after_patch);
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
}

TEST_CASE("from_ffi compat patch fails closed when the module is absent") {
  ResetTestHooks();
  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("not loaded") != std::string::npos);
}

TEST_CASE(
    "from_ffi compat patch succeeds when sha256 differs (version-agnostic)") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  g_digest[0] ^= 0xFF;  // Arbitrary/new SHA-256

  std::string error;
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
}

TEST_CASE("from_ffi compat patch dynamically locates Build 29667 RVA 0x49C27") {
  ResetTestHooks();
  FakeImage image;
  image.SetupSiteAt(0x49C27);
  g_image = &image;

  std::string error;
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
}

TEST_CASE(
    "from_ffi compat patch dynamically locates unhinted arbitrary RVA "
    "0x52100") {
  ResetTestHooks();
  FakeImage image;
  image.SetupSiteAt(0x52100);
  g_image = &image;

  std::string error;
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
}

TEST_CASE(
    "from_ffi compat patch succeeds when file hash cannot be read (diagnostic "
    "only)") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  g_hash_ok = false;

  std::string error;
  CHECK(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.empty());
  CHECK(image.SiteMatches(kFromFfiPatchedBytes));
}

TEST_CASE("from_ffi compat patch fails closed when signature is not found") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  image.SetSiteBytes(kUnknownSiteBytes);

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("signature not found") != std::string::npos);
  CHECK(g_protect_calls == 0);
}

TEST_CASE(
    "from_ffi compat patch fails closed when context anchors are missing") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  // Corrupt preceding anchor
  image.bytes[kFromFfiEventTypeCheckRva - 8] = 0x00;

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("signature not found") != std::string::npos);
  CHECK(g_protect_calls == 0);
}

TEST_CASE("from_ffi compat patch fails closed when the site is out of bounds") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  image.SetSizeOfImage(0x1000);

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK((error.find("outside") != std::string::npos ||
         error.find("signature not found") != std::string::npos));
  CHECK(image.SiteMatches(kFromFfiOriginalBytes));
}

TEST_CASE("from_ffi compat patch fails closed on a non-PE mapping") {
  ResetTestHooks();
  FakeImage image;
  image.bytes.assign(kFakeImageSize, 0);
  g_image = &image;

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("DOS header") != std::string::npos);
}

TEST_CASE("from_ffi compat patch fails closed when protect fails") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  g_fail_protect_on_call = 1;

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("VirtualProtect") != std::string::npos);
  CHECK(image.SiteMatches(kFromFfiOriginalBytes));
}

TEST_CASE("from_ffi compat patch reverts when the protect restore fails") {
  ResetTestHooks();
  FakeImage image;
  g_image = &image;
  // First protect succeeds (patch applied); the restore protect fails.
  g_fail_protect_on_call = 2;

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(TestHooks(), &error));
  CHECK(error.find("restore failed") != std::string::npos);
  // Fail-closed: a false result must not leave the patch live.
  CHECK(image.SiteMatches(kFromFfiOriginalBytes));
}

TEST_CASE("from_ffi compat patch rejects incomplete hooks") {
  ResetTestHooks();
  CompatPatchHooks hooks = TestHooks();
  hooks.protect = nullptr;

  std::string error;
  CHECK_FALSE(ApplyFromFfiCompatPatchWithHooks(hooks, &error));
  CHECK(error.find("incomplete") != std::string::npos);
}
