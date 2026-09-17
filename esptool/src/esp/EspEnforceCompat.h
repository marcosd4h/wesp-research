#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <string>

#include "esp/EspEventIds.h"

namespace esptool::esp {

// Compatibility shim for the espclient.dll client-side enforce gate.
//
// The wesp driver decides whether the enforcing action (client selector 5 ->
// RuleAction_::from_incoming action 3) is allowed by testing bit 0x02 of the
// per-event-type capability record. That bit is an ACCEPTANCE flag, not a
// blocking guarantee: a type is enforceable only when the driver also
// dispatches a pre-operation callback that writes a disposition (see the
// driver-ready deny set below). The client library, however, refuses the
// enforcing descriptor for every event type except 2000 (naturally), 3007,
// 8000, and 8001:
//
//   espclient_rs::rule::modify::EventModify::from_ffi(out rcx, edx event_type,
//                                                     r8 kind_desc)
//
// accepts 2000 only when the descriptor kind is 3, and returns error tag 5 with
// code 109 for everything else. The gate is a client build limitation, not a
// driver limitation, so it can be removed in memory for this process.
//
// The verified espclient.dll build is 1,108,088 bytes with
//   sha256 6ea81fe48b9068ff893ae76ebd00f5e7e1397d422b71ba48477d64a3f5ef73f8
// EventModify::from_ffi is at RVA 0x484F0. Its event-type check is:
//
//   RVA 0x48515  81 FA D0 07 00 00   cmpl $0x7d0, %edx   ; event_type vs 2000
//   RVA 0x4851B  0F 84 07 01 00 00   je   0x180048628   ; FoCreate kind-3 path
//
// Rewriting the six bytes at 0x48515 to 39 D2 90 90 90 90 (cmpl %edx,%edx plus
// four NOPs) forces ZF=1, so the following je is always taken and every event
// type that reaches the check takes the FoCreate kind-3 path. The patched
// client then yields the enforcing descriptor, which the driver accepts for the
// enforceable event types. Acceptance is not enforcement: see the driver-ready
// deny set below for the types that also write a disposition.

// EventModify::from_ffi is at RVA 0x484F0 (Build 29641) or 0x49BF0 (Build
// 29667). Its event-type check instruction sequence is:
//
//   cmpl $0x7d0, %edx   ; event_type vs 2000 (81 FA D0 07 00 00)
//   je   loc_FoCreate   ; FoCreate kind-3 path (0F 84 ... or 74 ...)
//
// Rewriting the six bytes at the check site to 39 D2 90 90 90 90 (cmpl
// %edx,%edx plus four NOPs) forces ZF=1, so the following je is always taken
// and every event type that reaches the check takes the FoCreate kind-3 path.
// The patched client then yields the enforcing descriptor, which the driver
// accepts for the enforceable event types. Acceptance is not enforcement: see
// the driver-ready deny set below for the types that also write a disposition.

// Event-type check bytes at the patch site: cmpl $0x7d0, %edx.
inline constexpr std::uint8_t kFromFfiOriginalBytes[6] = {0x81, 0xFA, 0xD0,
                                                          0x07, 0x00, 0x00};

// Patched bytes: cmpl %edx, %edx (39 D2) + four NOPs. Forces ZF=1.
inline constexpr std::uint8_t kFromFfiPatchedBytes[6] = {0x39, 0xD2, 0x90,
                                                         0x90, 0x90, 0x90};

inline constexpr std::size_t kFromFfiPatchBytes = sizeof(kFromFfiPatchedBytes);

// Structural context anchors in EventModify::from_ffi:
// 1. Preceding anchor: cmpl $0x1f3f, %edx (event_type vs 7999)
inline constexpr std::uint8_t kFromFfiPrecedingAnchor[6] = {0x81, 0xFA, 0x3F,
                                                            0x1F, 0x00, 0x00};
// 2. Following anchor: cmpl $0x0bbf, %edx (event_type vs 3007)
inline constexpr std::uint8_t kFromFfiFollowingAnchor[6] = {0x81, 0xFA, 0xBF,
                                                            0x0B, 0x00, 0x00};

// Measured instruction adjacency window bounds:
// On verified builds (e.g. 29641 and 29667):
// - cmpl $0x1f3f, %edx precedes the patch site by exactly 8 bytes (site - 8).
// - cmpl $0x0bbf, %edx follows the patch site by exactly 12 bytes (site + 12).
// Max lookback/lookahead windows provide measured tolerance:
inline constexpr std::size_t kFromFfiPrecedingMaxDistance = 16;
inline constexpr std::size_t kFromFfiFollowingMaxDistance = 24;

// Known historical check RVAs (used as candidate search hints, subject to full
// structural validation):
inline constexpr std::uintptr_t kKnownCandidateRvas[] = {
    0x48515,  // Build 29641 (1,108,088 bytes)
    0x49C27,  // Build 29667 (1,122,960 bytes)
};

// Legacy RVA constants retained for backward compatibility.
inline constexpr std::uintptr_t kFromFfiRva = 0x484F0;
inline constexpr std::uintptr_t kFromFfiEventTypeCheckRva = 0x48515;

// Historical sha256 of the 29641 build.
inline constexpr std::uint8_t kEnforceCompatExpectedSha256[32] = {
    0x6e, 0xa8, 0x1f, 0xe4, 0x8b, 0x90, 0x68, 0xff, 0x89, 0x3a, 0xe7,
    0x6e, 0xbd, 0x00, 0xf5, 0xe7, 0xe1, 0x39, 0x7d, 0x42, 0x2b, 0x71,
    0xba, 0x48, 0x47, 0x7d, 0x64, 0xa3, 0xf5, 0xef, 0x73, 0xf8};

// Driver-ready deny set. An event type is in this set only when BOTH
// conditions hold:
//
//   (1) the per-event-type capability record in wesp.sys has the
//   enforce-capable
//       bit 0x02 SET, and
//   (2) the driver dispatches a pre-operation callback for the type that can
//       WRITE a disposition (the FS/KTM callback writes qword_1803BB230; the
//       process notify callback writes dword_1803C66A4).
//
// The two conditions are encoded separately below, so neither can silently
// widen the set. DriverEventCapabilityMask is the wesp.sys Event Capability
// Bitmask table (bit 0x02 is the enforce-capable bit) and
// IsDispositionWritingCallback is the explicit set of types whose pre-operation
// callback writes a disposition. IsEnforceCompatEventType is the intersection
// of the two.
//
// The 0x02 bit is an ACCEPTANCE flag, not a blocking guarantee. The registry
// range is the counterexample that drives the exclusion below: RegCreateKey
// (7000) has the bit set and a rule installs, but the registry callback's
// blockable classes are delete-key, set-value, delete-value, rename,
// query-value, restore, save, and query-keyname; create-key and open-key have
// no disposition, so the key is still created. Enforcement is not even
// constructible for the range: RegSetValueKey (7003) fails EspCreateRule with
// 0x80070057 E_INVALIDARG even with the patch, because no registry enforcing
// descriptor can be built. 7000-7014 is therefore excluded.
//
// Included (both conditions):
//   1000            process create            (process notify disposition)
//   2001-2003       FoOpen/Read/Write         (FS disposition)
//   3000-3008 minus 3007 filesystem set       (FS disposition)
//   4000, 4002      VolumeMount, VolumeFsctl  (FS disposition)
// Excluded:
//   2000            FoCreate: the unpatched client already accepts it
//   2004            FoCleanup: capability mask 0x09, bit 0x02 clear
//   3007            FileQueryOpen: no FS disposition for the query-open class
//   8000/8001       capability mask 0x19 (bit 0x02 clear; live-recorded 0x19),
//                   so the driver cannot enforce them
//   5000/6000       bit 0x02 set (mask 0x0B) but no pre-operation DENY callback
//   9000            no capability record in the driver table for this build OR
//                   bit 0x02 clear, and no pre-operation DENY callback
//   7000-7014       acceptance bit set but the class cannot block (no
//                   create/open disposition) and 7003 cannot even build

// Bit 0x02 of the driver's per-event-type capability record: the
// enforce-capable bit. Acceptance only; see the two-condition derivation above.
inline constexpr std::uint32_t kDriverEnforceCapableBit = 0x02;

// wesp.sys Event Capability Bitmask, keyed by event type. Returns 0 when the
// event type has no capability record on this build. This table is the
// authoritative source for condition (1), so a type cannot be added to the
// disposition set without a mask entry: a type with no record returns 0, has
// bit 0x02 clear, and IsDriverEnforceCapable returns false.
//
//   mask 0x03 -> 1000, 2001
//   mask 0x0B -> 2002, 2003, 3000..3008, 4000, 4002, 5000, 6000, 7002..7014
//   mask 0x1B -> 2000, 7000, 7001
//   mask 0x09 -> 2004, 3009       (bit 0x02 CLEAR)
//   mask 0x19 -> 8000, 8001       (bit 0x02 CLEAR; live-recorded 0x19)
//   no record -> 9000 and any type not listed above (bit 0x02 CLEAR)
[[nodiscard]] constexpr std::uint32_t DriverEventCapabilityMask(
    std::uint32_t event_type) noexcept {
  // 0x03: process create and file open.
  if (event_type == kEventProcessCreate || event_type == kEventFoOpen) {
    return 0x03;
  }
  // 0x1B: file create, registry create-key (7000), and the registry type after
  // it (7001).
  if (event_type == kEventFoCreate || event_type == kEventRegCreateKey ||
      event_type == kEventRegCreateKey + 1) {
    return 0x1B;
  }
  // 0x0B: file read/write, the filesystem range 3000..3008, volume mount and
  // fsctl, pipe and mailslot create, and registry 7002..7014.
  if (event_type == kEventFoRead || event_type == kEventFoWrite ||
      (event_type >= kEventFsMin && event_type <= kEventFsLockFile) ||
      event_type == kEventVolumeMount || event_type == kEventVolumeFsctl ||
      event_type == kEventPipeCreate || event_type == kEventMailslotCreate ||
      (event_type >= kEventRegCreateKey + 2 && event_type <= kEventRegMax)) {
    return 0x0B;
  }
  // 0x09 (bit 0x02 CLEAR): file cleanup and FileUnlock (3009), the filesystem
  // type after the enforce-capable lock boundary.
  if (event_type == kEventFoCleanup || event_type == kEventFsLockFile + 1) {
    return 0x09;
  }
  // 0x19 (bit 0x02 CLEAR): the object-manager pair. The live read of the
  // ObCreateHandle record is `40 1f 00 00 19 00 00 00` (event type 8000, flags
  // 0x19), so the pair carries a real mask whose enforce-capable bit is clear
  // rather than no record at all.
  if (event_type == kEventObCreateHandle ||
      event_type == kEventObDuplicateHandle) {
    return 0x19;
  }
  return 0;
}

// Condition (1): the driver capability record carries the enforce-capable bit.
[[nodiscard]] constexpr bool IsDriverEnforceCapable(
    std::uint32_t event_type) noexcept {
  return (DriverEventCapabilityMask(event_type) & kDriverEnforceCapableBit) !=
         0;
}

// Condition (2): the driver dispatches a pre-operation callback for this event
// type that can WRITE a disposition. Deliberately independent of the capability
// mask: 5000 and 6000 carry the acceptance bit (mask 0x0B) but their callbacks
// never write a disposition, 9000 has no capability record on this build, and a
// type can have a disposition callback while a future build clears the bit. The
// FS/KTM callback writes qword_1803BB230; the process notify callback writes
// dword_1803C66A4.
[[nodiscard]] constexpr bool IsDispositionWritingCallback(
    std::uint32_t event_type) noexcept {
  if (event_type == kEventProcessCreate) {
    return true;
  }
  if (event_type >= kEventFoOpen && event_type <= kEventFoWrite) {
    return true;
  }
  if (event_type >= kEventFsMin && event_type <= kEventFsLockFile &&
      event_type != kEventFsQueryOpen) {
    return true;
  }
  if (event_type == kEventVolumeMount || event_type == kEventVolumeFsctl) {
    return true;
  }
  return false;
}

// The compat set is the intersection of the two conditions. Deriving it instead
// of enumerating it makes the 2004 error structurally impossible: 2004 is not a
// disposition-writing callback (the Fo range is 2001..2003) and its capability
// mask 0x09 has bit 0x02 clear, so it fails both conditions.
[[nodiscard]] constexpr bool IsEnforceCompatEventType(
    std::uint32_t event_type) noexcept {
  return IsDriverEnforceCapable(event_type) &&
         IsDispositionWritingCallback(event_type);
}

// Compile-time membership guards for the compat set and its driving exclusions.
// A regression that widens the set (for example, re-adding 2004) fails to
// compile where the byte-signature and mask tables are defined.
static_assert(IsEnforceCompatEventType(kEventProcessCreate),
              "process create writes a disposition and is enforce-capable");
static_assert(IsEnforceCompatEventType(kEventFoOpen), "FoOpen is enforceable");
static_assert(IsEnforceCompatEventType(kEventFoRead), "FoRead is enforceable");
static_assert(IsEnforceCompatEventType(kEventFoWrite),
              "FoWrite is enforceable");
static_assert(!IsEnforceCompatEventType(kEventFoCreate),
              "FoCreate is accepted natively and is not widened");
static_assert(!IsEnforceCompatEventType(kEventFoCleanup),
              "FoCleanup capability mask 0x09 has the enforce bit clear");
static_assert(!IsEnforceCompatEventType(kEventFsQueryOpen),
              "FileQueryOpen has no FS disposition for the query-open class");
static_assert(!IsEnforceCompatEventType(kEventPipeCreate),
              "PipeCreate has the bit but no disposition callback");
static_assert(!IsEnforceCompatEventType(kEventRegCreateKey),
              "registry create has no create/open disposition");
static_assert(!IsDriverEnforceCapable(kEventFoCleanup),
              "FoCleanup must not be driver-enforce-capable");
static_assert(!IsDriverEnforceCapable(kEventObCreateHandle),
              "ObCreateHandle record 0x19 must not be driver-enforce-capable");
static_assert(
    !IsDriverEnforceCapable(kEventObDuplicateHandle),
    "ObDuplicateHandle record 0x19 must not be driver-enforce-capable");

// Copies of the original and patched six-byte sequences are defined above as
// kFromFfiOriginalBytes / kFromFfiPatchedBytes.

// Injectable seam for the from_ffi patch. Production callers use
// DefaultCompatPatchHooks(); tests substitute deterministic hooks so the
// fail-closed paths (module absent, identity mismatch, unexpected site bytes,
// protect failure) can be exercised without the real DLL.
struct CompatPatchHooks {
  // Returns the base address of the mapped espclient.dll image, or nullptr
  // when the module is not loaded in this process.
  void* (*module_base)() = nullptr;
  // Computes the sha256 of the module image's on-disk file.
  bool (*file_sha256)(void* module_base, std::array<std::uint8_t, 32>& digest,
                      std::string& error) = nullptr;
  // Changes the page protection for [address, address + size).
  bool (*protect)(void* address, std::size_t size, unsigned long new_protect,
                  unsigned long* old_protect) = nullptr;
};

// Production hooks: GetModuleHandleW, the on-disk sha256, and VirtualProtect.
[[nodiscard]] CompatPatchHooks DefaultCompatPatchHooks();

// Locates the EventModify::from_ffi event-type check site inside the mapped
// espclient.dll image using structural ISA pattern matching and dual context
// anchors. Returns false if 0 or >1 matches are found.
[[nodiscard]] bool FindFromFfiPatchSite(const void* module_base,
                                        std::uintptr_t& out_rva,
                                        std::string& error);

// Applies the EventModify::from_ffi compat patch with the supplied hooks.
// In-memory only: the on-disk image is never modified. Idempotent (a second
// call returns true once the patched bytes are observed). Fails closed, writing
// a named diagnostic to *error when error is non-null, when the module is
// absent, when the patch site cannot be located uniquely, when the patch site
// is not inside the mapped executable image (parsed from the PE headers), or
// when the bytes at the patch site match neither the original nor the patched
// pattern. When the post-patch protect restore fails, the patch is reverted
// before returning false, so a false result never leaves the patch live.
[[nodiscard]] bool ApplyFromFfiCompatPatchWithHooks(
    const CompatPatchHooks& hooks, std::string* error);

// Applies the patch to the espclient.dll loaded in this process using the
// production hooks.
[[nodiscard]] bool ApplyFromFfiCompatPatch(std::string* error);

// Applies the EspRsCreateRule event-type sparse-range validation bypass. It
// changes the `jb` at RVA 0x27632 to an unconditional `jmp` so the client-side
// event-type gate accepts the OOB ranges 7015-7999 (and 3012-3999), letting the
// kernel to_index OOB be reached. In-memory only; idempotent.
[[nodiscard]] bool ApplyEventTypeBypassPatch(std::string* error);

}  // namespace esptool::esp
