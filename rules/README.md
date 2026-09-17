# Esptool XML Rule Document Specification and Reference

`tools/esptool/rules/` contains 118 XML documents consumed by `esptool`. `InstallRules` (`esp/EspRuleInstall.cpp`) reads document fields, not the leaf file name. The file name allows callers, automation scripts, and regression suites to identify the event, filter constructor, and action that each document installs.

The automated test runner (`tools/esptool/smoke/Run-EsptoolSmoke.ps1`) consumes this directory. `smoke/rules.manifest.json` records 118 manifest entries, matching the full on-disk inventory.

# Consumption Model and Session Contracts

`ParseRuleFile` (`model/RuleParser.cpp`) parses UTF-8 XML using the Windows XmlLite runtime within a single-threaded COM apartment. The parser strictly enforces numeric attribute formatting and ignores unknown elements. Grouping wrappers such as `<rules>` around `<rule>` children are accepted but ignored by the AST builder.

Commands that accept `--rules <path>`:

| Command              | Queue Allocation                                                   | Installation Gate                                                                        | Session Hold Interval                                                                |
| -------------------- | ------------------------------------------------------------------ | ---------------------------------------------------------------------------------------- | ------------------------------------------------------------------------------------ |
| `rules`              | Allocated only when at least one rule uses a queue-backed selector | `InstallRules`; exits with code 0 only on `InstallStatus::Complete`                      | `--duration` sleeps before `Disconnect` so in-path actions can intercept triggers    |
| `monitor`            | Same queue allocation rules as `rules`                             | Complete installation required                                                           | Pumps notifications; exits with code 0 only when at least one notification arrives   |
| `persist-rules`      | Same queue allocation rules as `rules`                             | Forces rule lifetime FFI to 3 (Persistent) on every rule, then enumerates persistent IDs | Leaves client registered when at least one persistent rule ID is verified            |
| `refs --from-notify` | Same queue allocation rules as `rules`                             | Complete installation required                                                           | Pumps one notification, then mints an object reference from the notification payload |
| `ipc rules`          | N/A                                                                | Transmits XML file bytes to the `esptool` service over the named pipe `\\.\pipe\esptool` | The service compiles and installs the document inside its protected context          |

Commands `rules`, `monitor`, `persist-rules`, and `refs` hop to a same-image child worker executing under `NT AUTHORITY\SYSTEM` with `SeTcbPrivilege` unless `--worker` is specified. Rule documents specifying `persist-rules` or named `deny` / `suppress` / Selector 5 / Selector 6 actions must not allocate a user-mode queue: the kernel persistent rule store rejects live user-mode queue handles with `E_INVALIDARG`.

Default client identity when `<client>` is omitted: client name `esptool`, altitude `385000` (`esp/EspCore.h`).

# XmlLite Parser Architecture and Grammar Rules

The parser implementation in `model/RuleParser.cpp` establishes strict syntax, hierarchy, and data validation rules.

## Document Boundaries and File Limits

- Root element: The document root must be `<esptool>`. If the initial element is not `<esptool>`, the parser aborts with `"root element must be <esptool>"`.
- File size ceiling: `ParseRuleFile` enforces a file size limit of 64 MiB (`kMaxRuleFileBytes = 64 * 1024 * 1024`). Files exceeding this size abort with `"the rule file is empty or too large"`.
- Combinator nesting ceiling: Filter tree recursion is bounded by `kMaxDepth = 16`. Pushing a combinator node when `stack.size() >= 16` aborts with `"filter nesting is too deep"`.
- Memory payload ceiling: String literals and collection text entries are capped at 65,535 bytes in UTF-16 encoding (`kMaxUtf16Bytes`).

## Token and Case-Sensitivity Rules

- Element local names and attribute names: Attribute and element names are retrieved from XmlLite and converted to ASCII lowercase (`text::ToLowerAscii`). As a result, attribute naming is case-insensitive: `eventType`, `eventtype`, `modifyKind`, and `modifykind` parse identically.
- Attribute string values: Attribute values are preserved with original casing, except where specific enum parsers perform normalization (`query kind`, `context`, `collection open`, `collection type`, `disposition`, and `lifetime`).
- Action token matching: `action` parsing first attempts unsigned numeric decoding. If the value is non-numeric, it tests against exact string literals `"deny"` and `"suppress"`.
- Empty elements: In XmlLite, self-closing tags (`<rule .../>`, `<collection .../>`, `<entry/>`) do not emit an `XmlNodeType_EndElement` event. The parser finalizes the node immediately upon reading the start tag.

## Element Placement and Hierarchy Constraints

The parser enforces a strict element hierarchy:

- `<rule>` cannot be nested inside another `<rule>`: aborts with `"<rule> cannot be nested"`.
- `<collections>` and `<collection>` cannot appear inside `<rule>`: aborts with `"<collections> cannot appear inside <rule>"` or `"<collection> cannot appear inside <rule>"`.
- `<entry>` must appear directly inside `<collection>`: aborts with `"<entry> must appear inside <collection>"`.
- `<filter>`, `<query>`, `<and>`, `<or>`, `<xor>`, and `<not>` must appear inside `<rule>`: aborts with `"<element> must appear inside <rule>"`.
- Unrecognized elements: Tags other than `esptool`, `client`, `rule`, `collections`, `collection`, `entry`, `query`, `filter`, `and`, `or`, `xor`, and `not` are ignored without error, allowing forward compatibility.

## Complete Parser Error Catalog

When XML parsing fails, `model/RuleParser.cpp` returns `ParseOutcome` with `ok = false` and a descriptive error string. Syntax and schema validation errors encountered during XmlLite element and attribute parsing append line numbers formatted as `"<message> (line N)"`. File I/O, COM initialization, and document-level failures do not carry line numbers. The complete catalog of parser error strings comprises:

| Error String                                                                 | Trigger Condition                                                              |
| ---------------------------------------------------------------------------- | ------------------------------------------------------------------------------ |
| `COM initialization failed`                                                  | `CoInitializeEx` failed before creating the XmlLite reader                     |
| `could not create an input stream for the rule document`                     | `SHCreateMemStream` failed to allocate stream memory                           |
| `could not create the XML reader`                                            | `CreateXmlReader` failed to instantiate `IXmlReader`                           |
| `could not bind the rule document to the XML reader`                         | `IXmlReader::SetInput` returned an error HRESULT                               |
| `could not open the rule file (error <Win32ErrorCode>)`                      | `CreateFileW` failed to open file path                                         |
| `could not read the rule file (error <Win32ErrorCode>)`                      | `ReadFile` failed during file ingestion                                        |
| `the rule file is empty or too large`                                        | File size on disk is 0 bytes or exceeds 64 MiB                                 |
| `the rule document is empty`                                                 | XML text buffer contains zero characters                                       |
| `the XML document is not well formed`                                        | XmlLite reported a syntax or well-formedness error                             |
| `root element must be <esptool>`                                             | First non-whitespace element is not `<esptool>`                                |
| `the <esptool> root element is not closed`                                   | Reader reached EOF without encountering `</esptool>`                           |
| `unterminated <rule> element`                                                | Rule element lacks a closing tag                                               |
| `<rule> cannot be nested`                                                    | `<rule>` encountered while a rule is currently open                            |
| `<collections> cannot appear inside <rule>`                                  | `<collections>` placed within `<rule>`                                         |
| `<collection> cannot appear inside <rule>`                                   | `<collection>` placed within `<rule>`                                          |
| `<entry> must appear inside <collection>`                                    | `<entry>` encountered outside `<collection>`                                   |
| `<query> must appear inside <rule>`                                          | `<query>` encountered outside `<rule>`                                         |
| `<filter> must appear inside <rule>`                                         | `<filter>` encountered outside `<rule>`                                        |
| `<and> must appear inside <rule>`                                            | Combinator tag encountered outside `<rule>`                                    |
| `<or> must appear inside <rule>`                                             | Combinator tag encountered outside `<rule>`                                    |
| `<xor> must appear inside <rule>`                                            | Combinator tag encountered outside `<rule>`                                    |
| `<not> must appear inside <rule>`                                            | Combinator tag encountered outside `<rule>`                                    |
| `filter nesting is too deep`                                                 | Combinator recursion depth reached 16 levels                                   |
| `mismatched </and>`                                                          | Closing `</and>` does not match active combinator on stack                     |
| `mismatched </or>`                                                           | Closing `</or>` does not match active combinator on stack                      |
| `mismatched </xor>`                                                          | Closing `</xor>` does not match active combinator on stack                     |
| `mismatched </not>`                                                          | Closing `</not>` does not match active combinator on stack                     |
| `client guid is not a valid GUID`                                            | `<client guid="...">` is not 32 hexadecimal digits                             |
| `rule eventType is not a number`                                             | `<rule eventType="...">` is not an unsigned decimal or hex integer             |
| `rule lifetime must be persistent or transient`                              | `<rule lifetime="...">` is not `persistent` or `transient`                     |
| `rule flags is not a number`                                                 | `<rule flags="...">` is not an unsigned integer                                |
| `rule action is not a number or a known action name (deny, suppress)`        | `<rule action="...">` is neither an integer nor `deny`/`suppress`              |
| `rule selector is not a number`                                              | `<rule selector="...">` is not an unsigned integer                             |
| `rule modifier is not a number`                                              | `<rule modifier="...">` is not an unsigned integer                             |
| `rule modifyKind is not a number`                                            | `<rule modifyKind="...">` is not an unsigned integer                           |
| `rule disposition must be access_denied, not_found, virus, or a number 1..5` | `<rule disposition="...">` does not match valid tokens or numbers 1 to 5       |
| `filter type is not a number`                                                | `<filter type="...">` is not a signed integer                                  |
| `filter comparand is not a number`                                           | `<filter comparand="...">` is not a signed integer                             |
| `filter operand is not a number`                                             | `<filter operand="...">` is not an unsigned 64-bit integer                     |
| `filter property is not a number`                                            | `<filter property="...">` is not an unsigned 32-bit integer                    |
| `query kind is required`                                                     | `<query>` tag lacks `kind` attribute                                           |
| `query kind is not recognized`                                               | `<query kind="...">` does not resolve to a recognized query export             |
| `query properties must be unsigned integers`                                 | `<query properties="...">` contains invalid non-numeric tokens                 |
| `query context must be set, enum, or both`                                   | `<query context="...">` contains tokens other than `set` or `enum`             |
| `collection type must be integer, string, or binary`                         | `<collection type="...">` is not `integer`, `string`, `binary`, or `1`/`2`/`3` |
| `collection guid is not a valid GUID`                                        | `<collection guid="...">` is not 32 hexadecimal digits                         |
| `open="true" requires guid`                                                  | `<collection open="true">` lacks a `guid` attribute                            |

# Complete Schema Specification

## Document Root: `<esptool>`

The root element of every valid document. Accepts no attributes. Contains child elements `<client>`, optional `<collections>`, and `<rules>`.

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <!-- Client configuration -->
  <!-- Optional collections -->
  <!-- Rules -->
</esptool>
```

## Client Configuration: `<client>`

Configures the registration descriptor passed to `EspRegisterClient`. If omitted, default values are assigned.

```xml
<client name="esptool-example" altitude="385000" guid="{a1b2c3d4-e5f6-7890-1234-56789abcdef0}"/>
```

| Attribute  | Data Type   | Default Value | Description                                                                                                                                                 |
| ---------- | ----------- | ------------- | ----------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`     | String      | `esptool`     | Client identity name string registered with the driver.                                                                                                     |
| `altitude` | String      | `385000`      | Filter Manager registration altitude. Defender recipes use altitude `328000`.                                                                               |
| `guid`     | GUID String | (Null GUID)   | Explicit client GUID. Must be exactly 32 hex digits (optional braces and hyphens). If omitted, `esptool` generates a unique random GUID via `CoCreateGuid`. |

### Altitude Collision Avoidance Loop

When `EspRegisterClient` returns `0x800700B7` (`ERROR_ALREADY_EXISTS`), `EspSession` executes an automated collision avoidance loop: it performs up to 32 retries (`kAltitudeCollisionTries = 32`), incrementing the base altitude by 10 (`kAltitudeCollisionStep = 10`) on each iteration (testing `385010`, `385020`, up to `385310`).

## Rule Specification: `<rule>`

Defines an individual rule descriptor submitted to `EspCreateRule`.

```xml
<rule name="deny-proc" event="ProcessCreate" eventType="1000"
      lifetime="transient" action="deny" disposition="access_denied"
      flags="0" selector="5" modifier="1" modifyKind="3">
  <!-- Predicates, Queries -->
</rule>
```

| Attribute     | Data Type        | Default Value         | Description                                                                                                                                                                                                                 |
| ------------- | ---------------- | --------------------- | --------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `name`        | String           | `""`                  | Descriptive label used in diagnostic logs and step reports.                                                                                                                                                                 |
| `eventType`   | Unsigned 32-bit  | Inferred from `event` | Sparse ABI event type identifier. Takes precedence over `event`.                                                                                                                                                            |
| `event`       | String           | `""`                  | Event name label. Supports three aliases if `eventType` is omitted: `ProcessCreate` (1000), `FileCreate` or `fo_create` (2000), `RegCreateKey` (7000). Any other string yields event type 0 and is skipped at installation. |
| `lifetime`    | Enum String      | `transient`           | Persistence tier: `transient` (FFI value 1) or `persistent` (FFI value 3).                                                                                                                                                  |
| `flags`       | Unsigned 32-bit  | `0`                   | Configuration flags written to rule descriptor offset `+28`.                                                                                                                                                                |
| `action`      | Numeric or Token | `0`                   | Action selector. Accepts any unsigned integer (raw selector) or exact string tokens `"deny"` (Selector 5) and `"suppress"` (Selector 4). Values `0`, `1`, or omitted resolve to Selector 1 (Queue-backed telemetry).        |
| `selector`    | Unsigned 32-bit  | (Unset)               | Action selector override. If specified alongside a named action, it must agree with the named action or installation is refused.                                                                                            |
| `modifier`    | Unsigned 32-bit  | (Unset)               | Overrides the rule descriptor `lifetime` field at offset `+24`.                                                                                                                                                             |
| `modifyKind`  | Unsigned 32-bit  | (Unset)               | Sets `modify_kind_override`, overriding the kernel disposition code written to descriptor offset `+1112` low DWORD.                                                                                                         |
| `disposition` | Token or Integer | (Unset)               | Selects the kernel return status for enforcing rules. Parsed after `modifyKind` and overwrites `modify_kind_override`. Low 32 bits are written to `descriptor.event_queue` at offset `+1112`.                               |

### Closed Set of Event Name Aliases

When `eventType` is omitted, the parser resolves only these three case-insensitive names:

- `ProcessCreate` resolves to sparse event type `1000`.
- `FileCreate` and `fo_create` resolve to sparse event type `2000`.
- `RegCreateKey` resolves to sparse event type `7000`.

All other event names (such as `PipeCreate`, `ThreadStart`, `FoOpen`) require an explicit numeric `eventType="..."`. If `eventType` is omitted and the name is not in this alias set, the event type becomes `0`, and `InstallRules` skips the rule with a diagnostic warning.

### Action Selectors and Dispatch Semantics

| Selector Value | Symbolic Constant       | Queue Required | Execution Semantics                                                                                                                                                                                                                          |
| -------------- | ----------------------- | -------------- | -------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `1`            | `kActionQueueBacked`    | Yes            | Telemetry rule. Event envelopes are generated and placed into the client event queue. Default for `action="0"`, `action="1"`, or omitted `action`.                                                                                           |
| `4`            | `kActionNotifySuppress` | No             | Telemetry suppression. Evaluated in notify form with zero EventModify count. The matching operation completes normally, but telemetry queuing is suppressed. Selected by `action="suppress"` or raw `action="4"`. Does not block operations. |
| `5`            | `kActionRewrite` (Deny) | No             | Active policy enforcement. The driver rewrites pre-operation parameters or returns an immediate blocking status (`FLT_PREOP_COMPLETE` or `CreationStatus` denial). Selected by `action="deny"` or raw `action="5"`.                          |
| `6`            | `kActionCancel`         | No             | Post-operation cancellation. Signals abortion to the driver callback stack.                                                                                                                                                                  |
| `7`            | `kActionMatchSubrules`  | No             | Subrule chaining. Evaluates dependent subrules anchored to the predecessor rule created in the same session. Subrule count and handle array pointer are written to offsets `+1112` and `+1120`.                                              |

### Rule Disposition Codes and Kernel Status Mapping

The `disposition` attribute on an enforcing `<rule>` selects the kernel status code written by `wesp.sys` pre-operation callbacks when an enforcing rule matches. The low 32-bit DWORD of `RuleDescriptor.event_queue` (offset `+1112`) carries this value.

In the kernel driver, `qword_1803BB230` (filesystem pre-create disposition table) and `dword_1803C66A4` (process-creation notify status table) are 5-entry lookup tables indexed as `index = code - 1` (user disposition codes 1 through 5 select kernel slots 0 through 4):

| Keyword                                   | Code | Kernel NTSTATUS                        | Win32 Error Code                      | User-Visible Effect                                          |
| ----------------------------------------- | ---- | -------------------------------------- | ------------------------------------- | ------------------------------------------------------------ |
| `virus` or `virus_infected`               | 1    | `STATUS_VIRUS_INFECTED` (`0xC0000906`) | `ERROR_VIRUS_INFECTED` (`0x800700E1`) | Operation blocked due to malware infection detected (slot 0) |
| `access_denied`, `denied`, `accessdenied` | 2    | `STATUS_ACCESS_DENIED` (`0xC0000022`)  | `ERROR_ACCESS_DENIED` (`0x80070005`)  | Returns standard "Access is denied." (slot 1)                |
| `not_found` or `notfound`                 | 3    | `STATUS_NOT_FOUND` (`0xC0000225`)      | `ERROR_NOT_FOUND` (`0x80070490`)      | Target not found / blocks file creation (slot 2)             |
| (numeric)                                 | 4    | `STATUS_ACCESS_DENIED` (`0xC0000022`)  | `ERROR_ACCESS_DENIED` (`0x80070005`)  | Access denied (kernel table slot 3)                          |
| (numeric)                                 | 5    | `STATUS_ACCESS_DENIED` (`0xC0000022`)  | `ERROR_ACCESS_DENIED` (`0x80070005`)  | Access denied (kernel table slot 4)                          |

#### Binary Descriptor Placement

When `EspCreateRule` constructs the binary descriptor for Selector 5 (`kActionRewrite`):

- `descriptor.event_queue` (offset `+1112`): The low 32-bit DWORD carries `disposition_param = spec.modify_kind_override.value_or(kind)`. High bits remain zero so the driver does not interpret it as a user-mode queue handle.
- `descriptor.event_modify_count` (offset `+1088`): Stores the inner `EventModify` kind (`3` for `FoCreate` and enforce-compat rules).
- `descriptor.event_modify_size` (offset `+1092`): Stores the AccessMask payload size (`16` bytes).
- `descriptor.event_modify_ptr` (offset `+1096`): Points to the 16-byte `EventModifyBlob` list header containing `AccessMaskModification` (mask `0x120089`).

#### Subsystem Callback Enforcement Mechanics

- Process Creation (`1000`): The `PsSetCreateProcessNotifyRoutineEx` callback writes the error status corresponding to the disposition into `PS_CREATE_NOTIFY_INFO.CreationStatus`. User-mode process creation fails immediately with `0x80004005` (`E_FAIL`) or `STATUS_ACCESS_DENIED`.
- Filesystem Operations (`2000` through `2003`, `3000` through `3008`): The minifilter pre-operation callback sets `Data->IoStatus.Status` to the selected NTSTATUS code and returns `FLT_PREOP_COMPLETE`. For `FoCreate` (`2000`), disposition 3 returns `STATUS_NOT_FOUND`, preventing file creation.

# Policy Enforcement and Enforce-Compat Mechanism

WESP implements a two-sided gate model that governs whether an enforcing rule (`action="deny"`) can be armed.

## The Two-Sided Enforcement Gate

To successfully install an enforcing rule, two independent gates must be satisfied:

1. User-Mode Client Gate (`EventModify::from_ffi`): In an unpatched `espclient.dll`, the function `EventModify::from_ffi` validates the event type before constructing an enforcing rule descriptor. It restricts kind-3 `AccessMask` modification descriptors exclusively to `FoCreate` (`2000`), while routing `8000` through kind 1, `8001` through kind 2, and `3007` through kind 4. All other event types fail with `0x80070057` (`E_INVALIDARG`).
2. Kernel Driver Gate (`RuleAction::from_incoming`): When `wesp.sys` receives a rule descriptor, it inspects internal capability bitmasks and callback registration tables. The driver requires capability bit `0x02` (`EnforceCapable`) and mandates that the subsystem pre-operation callback supports status modification (such as writing to `PS_CREATE_NOTIFY_INFO.CreationStatus` or returning `FLT_PREOP_COMPLETE`).

An unmodified `espclient.dll` prevents researchers from deploying deny rules on events that the kernel driver is fully equipped to enforce, such as Process Creation (`1000`) and File Open (`2001`).

## In-Memory Patch Mechanics: enforce-compat

To bypass the client-side restriction without modifying binary files on disk, `esptool` provides the `--enforce-compat` flag.

When `--enforce-compat` is enabled, `esptool` applies an in-memory binary patch to `espclient.dll` within its own process space using dynamic structural pattern matching:

1. Diagnostic Digest Logging: It reads `espclient.dll` and computes its SHA-256 hash for diagnostic telemetry (historical reference build 29641 has size 1,108,088 bytes and SHA-256 `6ea81fe48b9068ff893ae76ebd00f5e7e1397d422b71ba48477d64a3f5ef73f8`; build 29667 has size 1,122,960 bytes).
2. Dual-Anchor Structural Location: Instead of relying exclusively on static RVAs, `FindFromFfiPatchSite` enumerates all executable sections (`IMAGE_SCN_MEM_EXECUTE`) in the mapped module. It evaluates known candidate hint RVAs (`0x48515` on Build 29641, `0x49C27` on Build 29667) and executes a search validated by two structural context anchors:
   - Preceding Anchor: Asserts that `cmpl $0x1f3f, %edx` (`81 FA 3F 1F 00 00`, event type versus 7999) is present within 16 bytes before the candidate patch site.
   - Following Anchor: Asserts that `cmpl $0x0bbf, %edx` (`81 FA BF 0B 00 00`, event type versus 3007) is present within 24 bytes following the jump instruction (`je`, opcode `0x74` or `0x0F 0x84`).
3. Idempotent In-Memory Rewrite:
   - If the memory already matches `kFromFfiPatchedBytes`, `esptool` logs that the patch is already active and returns success immediately.
   - Otherwise, it changes page protection via `VirtualProtect` to `PAGE_EXECUTE_READWRITE`.
   - It rewrites six bytes: `cmpl $0x7d0, %edx` (`81 FA D0 07 00 00`) is replaced with `cmpl %edx, %edx` (`39 D2`) followed by four NOP instructions (`90 90 90 90`).
   - It restores the original page protection and flushes the instruction cache.
4. Execution Effect: The rewritten instruction forces `ZF=1`, ensuring the conditional jump (`je`) is unconditionally taken. Every driver-ready event type reaching the check routes into the `FoCreate` kind-3 AccessMask descriptor constructor, generating a valid enforcing rule descriptor.

## Compatibility Event Set

An event type is in the compatibility set only when both conditions hold:

1. The per-event capability record in `wesp.sys` has capability bit `0x02` (`EnforceCapable`) set.
2. The driver dispatches a pre-operation callback that writes a disposition.

- Included: `1000` (ProcessCreate), `2001` through `2003` (FoOpen, FoRead, FoWrite), `3000` through `3008` except `3007` (Filesystem operations), `4000`, `4002` (Volume mount, Volume FSCTL).
- Excluded: `2000` (FoCreate, accepted natively), `2004` (FoCleanup, capability mask 0x09, bit 0x02 clear), `3007` (FS QueryOpen, lacks status modification), `5000`/`6000` (Named Pipe and Mailslot create, bit 0x02 set but no pre-operation DENY callback), `7000` through `7014` (Registry operations, lack callback disposition mapping; 7003 cannot build an enforcing descriptor), `8000`/`8001` (mask 0x19, bit 0x02 clear), `9000` (BootLoadDriver, no capability record).

Each Selector 5 rule is submitted individually. A mixed document arms every entry the driver accepts, and `InstallStatus::Partial` keeps the process exit code non-zero.

# Filter Leaves: `<filter>`

A filter leaf defines a single typed predicate evaluated by the ROBDD decision engine.

```xml
<filter type="10" comparand="1" property="1"
        value="$nt:C:\Windows\System32\cmd.exe"
        collection="cmd-images" propertyName="imagePath" op="equals"/>
```

| Attribute      | Data Type       | Default Value | Description                                                                                                                        |
| -------------- | --------------- | ------------- | ---------------------------------------------------------------------------------------------------------------------------------- |
| `type`         | Signed 32-bit   | `0`           | Index into `kTypedFilterExports` (1 to 16). Value `0` indicates an empty filter.                                                   |
| `property`     | Unsigned 32-bit | `0`           | Target property identifier. Passed as first parameter to the constructor export.                                                   |
| `operand`      | Unsigned 64-bit | `0`           | Fallback value for `property` if `property` is omitted or zero.                                                                    |
| `comparand`    | Signed 32-bit   | `0`           | Relational operator code. If `collection` is specified and `comparand` is zero, auto-inferred as 4 (`kStringComparandCollection`). |
| `value`        | String          | `""`          | Immediate operand value. Paths prefixed with `$nt:` undergo Win32-to-NT device path expansion.                                     |
| `collection`   | String          | `""`          | Name of a document collection bound via Comparand 4.                                                                               |
| `propertyName` | String          | `""`          | Descriptive label for diagnostics and logs. Ignored by compiler.                                                                   |
| `op`           | String          | `""`          | Descriptive operator label for diagnostics. Ignored by compiler.                                                                   |

## Empty Filter Handling

A `<filter type="0"/>` element, or a `<rule>` containing no `<filter>` child, represents an empty filter. In `EspSession::IsEmptyFilter`, this condition is identified when `kind == Leaf`, `type == 0`, and `children.empty()`. For ProcessCreate (`1000`), an empty filter leaves the event-config pointer at offset `+96` null; attaching a non-null configuration blob to an empty rule suppresses notification delivery.

## Typed Filter Constructor Index (`type`)

The `type` attribute selects the DLL export invoked to construct the filter leaf handle:

| Index | Export Function                    | Target Subsystem                | Short Name            |
| ----- | ---------------------------------- | ------------------------------- | --------------------- |
| 1     | `EspCreateClientFilter`            | Client Identity                 | `client`              |
| 2     | `EspCreateDesktopFilter`           | Window Stations and Desktops    | `desktop`             |
| 3     | `EspCreateDiskFilter`              | Disk Device Objects             | `disk`                |
| 4     | `EspCreateEventFilter`             | Notification Events             | `event`               |
| 5     | `EspCreateFileFilter`              | Filesystem Namespace            | `file`                |
| 6     | `EspCreateFileObjectFilter`        | Executive File Objects          | `fileobject`          |
| 7     | `EspCreateFileStreamFilter`        | Alternate Data Streams          | `filestream`          |
| 8     | `EspCreateRegistryKeyFilter`       | Configuration Manager Key Paths | `registry_key`        |
| 9     | `EspCreateRegistryKeyObjectFilter` | Registry Key Objects            | `registry_key_object` |
| 10    | `EspCreateProcessFilter`           | Process Manager Entities        | `process`             |
| 11    | `EspCreateThreadFilter`            | Thread Entities                 | `thread`              |
| 12    | `EspCreateTokenFilter`             | Security Access Tokens          | `token`               |
| 13    | `EspCreateVolumeFilter`            | Storage Volumes                 | `volume`              |
| 14    | `EspCreatePipeFilter`              | Named Pipes                     | `pipe`                |
| 15    | `EspCreateMailslotFilter`          | Mailslot Objects                | `mailslot`            |
| 16    | `EspCreateKtmTransactionFilter`    | Kernel Transaction Manager      | `ktm`                 |

# Relational and Numeric Operator Specifications

Filter leaves map `<filter>` attributes onto typed memory structures determined by constructor type and property ID.

## String Comparands

String comparands use Size Class 4 (`StringComparandRaw`, 32 bytes) or Size Class 5 (`FilePathComparandRaw`, 40 bytes for File property 17):

| Comparand | Operator      | Structure                | Semantics                                                                            |
| --------- | ------------- | ------------------------ | ------------------------------------------------------------------------------------ |
| 1         | Equals        | `StringComparandRaw`     | Exact inline UTF-16 equality (`kStringKindInlineUtf16`)                              |
| 2         | Not Equals    | `StringComparandRaw`     | Asserts property string differs from operand                                         |
| 3         | Pattern Match | `StringComparandRaw`     | Evaluates string pattern across the in-kernel string trie engine                     |
| 4         | In Collection | `CollectionComparandRaw` | Evaluates membership in an in-kernel ROBDD collection (`kStringComparandCollection`) |

## Numeric Operators

Numeric comparands use Size Class 3 (`NumericComparandRaw`, 56 bytes). They are evaluated by `wesp.sys` inside `wesp_lib::filter::comparison::evaluate_numeric_op`:

| Comparand | Operator              | Symbol  | Evaluation Condition                                                             |
| --------- | --------------------- | ------- | -------------------------------------------------------------------------------- |
| 1         | Equal                 | `==`    | `val == operand`                                                                 |
| 2         | Not Equal             | `!=`    | `val != operand`                                                                 |
| 3         | Less Than             | `<`     | `val < operand`                                                                  |
| 4         | Less Than or Equal    | `<=`    | `val <= operand`                                                                 |
| 5         | Greater Than          | `>`     | `val > operand`                                                                  |
| 6         | Greater Than or Equal | `>=`    | `val >= operand`                                                                 |
| 7         | Mask Test (Subset)    | Bitwise | `(val & ~operand) == 0` (asserts all set bits in value are in operand)           |
| 8         | Disjoint              | Bitwise | `(val & operand) == 0` (asserts value and operand share no common bits)          |
| 9         | Overlap (Any Set)     | Bitwise | `(val & operand) != 0` (asserts at least one common bit is shared)               |
| 10        | In Collection         | Set     | Evaluates membership in an in-kernel integer collection (`Collection::contains`) |
| 11        | In Range (Between)    | Range   | `val >= min && val <= max` (evaluates dual-bound range membership)               |

## Boolean Comparands

Boolean comparands use Size Class 2 (`BoolComparandRaw`, 16 bytes). Equality is enforced (`kBoolComparandEquals = 1`). Immediate operand string `"1"` or `"true"` evaluates to 1; all other strings evaluate to 0.

## File Property 17 Path Wrapper

When `type="5"` (`EspCreateFileFilter`) targets property `17`, the payload is wrapped in `FilePathComparandRaw` (Size Class 5, 40 bytes). The structure places wrapper kind `1` at offset `+0` and embeds `StringComparandRaw` at offset `+8`.

## NT Path Prefix Expansion (`$nt:`)

The literal prefix `"$nt:"` triggers `ExpandFilterValue` in `esp/EspNtPath.cpp`:

1. Asserts `value.size() > 4` and begins with `"$nt:"`.
2. Strips the prefix and evaluates the Win32 path.
3. If the path contains a drive letter (for example, `C:\Windows`), it resolves the underlying volume device path via `QueryDosDeviceW` (yielding `\Device\HarddiskVolumeN`).
4. Traverses directory components using `FindFirstFileW` to normalize on-disk filesystem casing.
5. Emits the fully qualified NT device namespace string (for example, `\Device\HarddiskVolume3\Windows\System32\notepad.exe`).
6. Registry paths are not processed by `$nt:` expansion; they are specified directly as target registry path strings.

# Boolean Combinators: `<and>`, `<or>`, `<xor>`, `<not>`

Combinators assemble multiple filter nodes into composite decision trees.

```xml
<rule name="composite-rule" eventType="1000">
  <and>
    <filter type="10" comparand="1" property="1" value="$nt:C:\Windows\System32\cmd.exe"/>
    <filter type="1" comparand="1" property="1" value="1"/>
  </and>
</rule>
```

| Combinator | Arity                   | Export Function      | Excess Child Handling                                                                                                                      |
| ---------- | ----------------------- | -------------------- | ------------------------------------------------------------------------------------------------------------------------------------------ |
| `<and>`    | Binary (≥ 2 children)   | `EspCreateAndFilter` | Evaluates first two children (`children[0]` and `children[1]`). Excess siblings are retained in the AST but not passed to the constructor. |
| `<or>`     | Binary (≥ 2 children)   | `EspCreateOrFilter`  | Evaluates first two children. Excess siblings are stored but not sent.                                                                     |
| `<xor>`    | Binary (≥ 2 children)   | `EspCreateXorFilter` | Evaluates first two children. Excess siblings are stored but not sent.                                                                     |
| `<not>`    | Unary (exactly 1 child) | `EspCreateNotFilter` | Requires exactly one child. Compiling 0 or 2+ children returns `kInvalidArg`.                                                              |

## Implicit AND Evaluation

When multiple sibling `<filter>` elements appear directly under `<rule>` without an enclosing combinator tag, `FinalizeRule` wraps the sibling array into an implicit `<and>` node. The compiler forwards the first two siblings to `EspCreateAndFilter`.

# In-Kernel Collections: `<collections>`, `<collection>`, `<entry>`

Declares dynamic data sets evaluated directly by in-kernel decision graphs.

```xml
<collections>
  <collection name="cmd-images" type="string">
    <entry>$nt:C:\Windows\System32\cmd.exe</entry>
  </collection>
  <collection name="token-levels" type="integer">
    <entry>0</entry>
    <entry>12288</entry>
  </collection>
  <collection name="esp-bytes" type="binary">
    <entry>65-73-70</entry>
  </collection>
  <collection name="reopen" open="true" guid="{391d246d-f7bc-dd43-894a-0ab429fa8dad}"/>
</collections>
```

| Element / Attribute | Data Type   | Default Value  | Description                                                                           |
| ------------------- | ----------- | -------------- | ------------------------------------------------------------------------------------- |
| `<collection name>` | String      | `""`           | Symbolic collection name bound by `<filter collection="...">`.                        |
| `<collection type>` | Enum        | `string` (`2`) | Value type: `integer` (or `1`), `string` (or `2`), `binary` (or `3`).                 |
| `<collection open>` | Boolean     | `false`        | When `"true"` or `"1"`, opens an existing kernel collection by GUID. Requires `guid`. |
| `<collection guid>` | GUID String | (Null GUID)    | 32-hex GUID string required when `open="true"`.                                       |
| `<entry>`           | Text        | `""`           | Collection item text payload.                                                         |

## Collection Entry Decoding Rules

- `string` collections (Type 2): Entry text is processed by `ExpandFilterValue` (expanding `$nt:` prefixes to NT device paths). Must not be empty or exceed 65,535 bytes in UTF-16.
- `integer` collections (Type 1): Entry text is parsed as unsigned decimal or hex integer into a 64-bit integer.
- `binary` collections (Type 3): Entry text is parsed as hexadecimal bytes. Spaces, tabs, newlines, and hyphens (`-`) are stripped. The remaining hex string must have an even length, where each pair represents one byte (for example, `65-73-70` decodes to ASCII `ESP`).

# Post-Notification Queries: `<query>`

Attaches post-event inspection recipes to a rule. When a notification matching the rule arrives, `esptool` extracts the target object handle from the event envelope and queries the specified property IDs.

```xml
<query kind="process" properties="6,20,1,2" context="set,enum"/>
```

| Attribute    | Data Type  | Default Value | Description                                                                                    |
| ------------ | ---------- | ------------- | ---------------------------------------------------------------------------------------------- |
| `kind`       | String     | (Required)    | Executive object kind to query. Case-insensitive. Validated against `SupportExportForKind`.    |
| `properties` | CSV String | `""`          | Comma-separated list of unsigned integer property IDs to extract from the entity property bag. |
| `context`    | CSV String | `""`          | Context key manipulation flags. Accepts `set`, `enum`, or `set,enum`.                          |

## Supported Query Kinds and Canonical Aliases

- Canonical kinds: `client`, `desktop`, `disk`, `event`, `fileobject`, `file`, `filestream`, `ktm`, `mailslot`, `pipe`, `process`, `registry-key-object`, `registry`, `thread`, `token`, `volume`.
- Aliases: `process-token` and `thread-token` canonicalize to `token`; `stream` canonicalizes to `filestream`.

# Complete Property Catalog Across Executive Families

The following tables document all property identifiers, data types, and symbolic names decoded by `LookupPropertyName` (`EspNotifyFormat.cpp`):

## Process (Constructor 10, Query `process`)

| Property ID | Name               | Data Type | Description                           |
| ----------- | ------------------ | --------- | ------------------------------------- |
| 1           | `CommandLine`      | String    | Process command line string           |
| 2           | `SessionId`        | Integer   | Terminal Services session ID          |
| 3           | `ParentProcessId`  | Integer   | Parent process ID                     |
| 4           | `JobId`            | Integer   | Kernel job object ID                  |
| 5           | `Affinity`         | Integer   | Process CPU affinity mask             |
| 6           | `ProcessId`        | Integer   | Process ID (PID)                      |
| 7           | `ExitStatus`       | Integer   | Process termination exit code         |
| 8           | `CreateTime`       | Timestamp | Process creation timestamp            |
| 9           | `ExitTime`         | Timestamp | Process termination timestamp         |
| 10          | `KernelTime`       | Integer   | Kernel execution time quantum         |
| 11          | `UserTime`         | Integer   | User execution time quantum           |
| 12          | `ExitStatus`       | Integer   | Process termination exit code         |
| 13          | `UniqueProcessKey` | Integer   | 64-bit kernel process identity key    |
| 14          | `ProcessStartTime` | Timestamp | Process start timestamp               |
| 16          | `Wow64Process`     | Boolean   | True for 32-bit process on 64-bit OS  |
| 17          | `ProtectionLevel`  | Integer   | `PS_PROTECTION` level and signer byte |
| 18          | `MitigationFlags`  | Integer   | Process exploit mitigation policies   |
| 19          | `TokenElevation`   | Integer   | Primary token elevation type          |
| 20          | `ImagePath`        | String    | NT device path to executable binary   |
| 21          | `Subsystem`        | Integer   | Subsystem type (GUI, CUI)             |
| 22          | `Machine`          | Integer   | Target architecture machine code      |

## Thread (Constructor 11, Query `thread`)

| Property ID | Name                | Data Type | Description                      |
| ----------- | ------------------- | --------- | -------------------------------- |
| 1           | `ThreadId`          | Integer   | Unique thread ID (TID)           |
| 2           | `ProcessId`         | Integer   | Owning process ID                |
| 3           | `CreateTime`        | Timestamp | Thread creation timestamp        |
| 4           | `ExitTime`          | Timestamp | Thread termination timestamp     |
| 5           | `StartAddress`      | Pointer   | Thread entry point address       |
| 6           | `Subsystem`         | Integer   | Thread subsystem                 |
| 7           | `Win32StartAddress` | Pointer   | Win32 thread entry point address |

## FileObject (Constructor 6, Query `fileobject`)

| Property ID | Name             | Data Type | Description                                        |
| ----------- | ---------------- | --------- | -------------------------------------------------- |
| 1           | `FileName`       | String    | Relative or fully qualified file path              |
| 2           | `Disposition`    | Integer   | Create disposition (Open, Create, Overwrite)       |
| 3           | `AccessMask`     | Integer   | Desired access rights                              |
| 4           | `ShareAccess`    | Integer   | Sharing modes (Read, Write, Delete)                |
| 5           | `CreateOptions`  | Integer   | Options flags passed to `NtCreateFile`             |
| 6           | `FileAttributes` | Integer   | Filesystem attribute flags                         |
| 7           | `StreamName`     | String    | Alternate data stream name                         |
| 8           | `EndOfFile`      | Integer   | File size in bytes                                 |
| 9           | `VolumeName`     | String    | Volume name hosting the file                       |
| 10          | `FileIndex`      | Integer   | Volume directory index                             |
| 18          | `FileId`         | Integer   | 64-bit or 128-bit filesystem ID                    |
| 28          | `FileObjectType` | Integer   | Executive classification (value `3` is Named Pipe) |

## Registry (Constructor 8, Query `registry`)

| Property ID | Name         | Data Type   | Description                            |
| ----------- | ------------ | ----------- | -------------------------------------- |
| 1           | `KeyPath`    | String      | Fully qualified NT registry key path   |
| 2           | `ValueName`  | String      | Target registry value name             |
| 3           | `ValueType`  | Integer     | Registry data type (REG_SZ, REG_DWORD) |
| 4           | `ValueData`  | Binary Blob | Serialized value data payload          |
| 5           | `Class`      | String      | Registry key class string              |
| 6           | `TitleIndex` | Integer     | Key title index                        |

## Pipe and Mailslot (Constructors 14 and 15)

| Family   | Property ID | Name                | Data Type | Description                           |
| -------- | ----------- | ------------------- | --------- | ------------------------------------- |
| Pipe     | 1           | `PipeName`          | String    | Full named pipe NT device path        |
| Pipe     | 2           | `PipeConfiguration` | Integer   | Pipe mode and buffering configuration |
| Pipe     | 3           | `MaxInstances`      | Integer   | Maximum concurrent pipe instances     |
| Pipe     | 4           | `CurrentInstances`  | Integer   | Currently active pipe instance count  |
| Mailslot | 1           | `MailslotName`      | String    | Full mailslot path                    |
| Mailslot | 2           | `MaxMessageSize`    | Integer   | Maximum allowed message payload size  |
| Mailslot | 3           | `ReadTimeout`       | Integer   | Mailslot read timeout interval        |

## Token (Constructor 12, Query `token`)

| Property ID | Name                      | Data Type | Description                           |
| ----------- | ------------------------- | --------- | ------------------------------------- |
| 1           | `TokenUserSid`            | SID       | User account security identifier      |
| 2           | `TokenGroups`             | SID Array | Token group memberships               |
| 3           | `TokenPrivileges`         | Bitmask   | Token privileges array                |
| 4           | `TokenOwner`              | SID       | Token default owner SID               |
| 5           | `TokenPrimaryGroup`       | SID       | Token primary group SID               |
| 6           | `TokenDefaultDacl`        | ACL       | Token default discretionary ACL       |
| 7           | `TokenType`               | Integer   | Token type (Primary vs Impersonation) |
| 8           | `TokenImpersonationLevel` | Integer   | Token impersonation level             |
| 9           | `TokenElevationType`      | Integer   | Token elevation classification        |
| 10          | `TokenIntegrityLevel`     | SID       | Mandatory integrity level SID         |
| 11          | `TokenAppContainer`       | SID       | AppContainer package SID              |

## Desktop (Constructor 2, Query `desktop`)

| Property ID | Name          | Data Type | Description                |
| ----------- | ------------- | --------- | -------------------------- |
| 1           | `DesktopName` | String    | Desktop object name        |
| 2           | `SessionId`   | Integer   | Desktop session identifier |

## Volume and Filesystem (Constructors 13 and 5)

| Family     | Property ID | Name                   | Data Type | Description                              |
| ---------- | ----------- | ---------------------- | --------- | ---------------------------------------- |
| Volume     | 1           | `VolumeGuid`           | GUID      | Storage volume GUID identifier           |
| Volume     | 2           | `DeviceName`           | String    | NT volume device path                    |
| Volume     | 3           | `FileSystemType`       | Integer   | Filesystem driver type (NTFS, ReFS, FAT) |
| Volume     | 4           | `FsctlCode`            | Integer   | Filesystem control code                  |
| Filesystem | 1           | `FileName`             | String    | Fully qualified filesystem path          |
| Filesystem | 2           | `FileInformationClass` | Integer   | Information class requested              |
| Filesystem | 3           | `FileAccess`           | Integer   | Access rights granted or requested       |
| Filesystem | 4           | `AllocationSize`       | Integer   | Allocated cluster size in bytes          |
| Filesystem | 5           | `EndOfFile`            | Integer   | Current file length in bytes             |
| Filesystem | 6           | `FileAttributes`       | Integer   | Standard Windows filesystem attributes   |
| Filesystem | 7           | `SecurityInformation`  | Integer   | Security descriptor components           |
| Filesystem | 8           | `EaName`               | String    | Extended attribute name                  |
| Filesystem | 9           | `FsctlCode`            | Integer   | FSCTL operation dispatch code            |

## KTM, Handle, and Additional Objects

| Family | Property ID | Name              | Data Type | Description                                  |
| ------ | ----------- | ----------------- | --------- | -------------------------------------------- |
| KTM    | 1           | `TransactionId`   | GUID      | KTM transaction GUID                         |
| KTM    | 2           | `TransactionUow`  | GUID      | Unit of Work identifier                      |
| KTM    | 3           | `IsolationLevel`  | Integer   | Transaction isolation level                  |
| KTM    | 4           | `Timeout`         | Integer   | Transaction timeout interval in milliseconds |
| Handle | 1           | `Handle`          | Pointer   | Created or duplicated handle value           |
| Handle | 2           | `DesiredAccess`   | Integer   | Access mask requested by caller              |
| Handle | 3           | `GrantedAccess`   | Integer   | Access mask granted by Object Manager        |
| Handle | 4           | `TargetProcessId` | Integer   | Process receiving the handle                 |
| Handle | 5           | `SourceProcessId` | Integer   | Process holding the source handle            |

Object families without dedicated symbolic switch cases in `LookupPropertyName` (such as `Event`, `Client`, `Disk`, `FileStream`, and `RegistryKeyObject`) default to structured diagnostic format strings `{Family}Prop_{id}` in notification decoding output (for example, `EventProp_1`, `ClientProp_1`, `DiskProp_1`, `FileStreamProp_1`, and `RegistryKeyObjectProp_1`).

# Document Naming Conventions and Corpus Inventory

The 118 XML rule documents in `tools/esptool/rules/` follow a structured naming grammar:

## Single-Rule Grammar

`{role}_{event}_{filter}[_{qualifier}].xml`

`monitor_{event}.xml` without a filter field specifies an empty filter with queue-backed action (`0` or `1`).

## Multi-Rule Grammar

`{role}_multi_{seg1}_{seg2}_...xml`

Each segment represents `{filter}` or `{combinator}_{filter}` in document order.

Exception: When all rules share a single event and empty filters, the single-event form is retained with distinct actions in the qualifier (for example, `enforce_process_create_empty_queue_subrules.xml` installs Action 1 followed by Action 7).

## Roles

| Role      | Meaning                                                                                                 |
| --------- | ------------------------------------------------------------------------------------------------------- |
| `monitor` | Queue-backed telemetry install (Action 0 or 1). Uses empty filter unless a filter segment is specified. |
| `filter`  | Queue-backed install invoking one or more `EspCreate*Filter` constructors.                              |
| `enforce` | Real-time policy enforcement. Specifies `action="deny"`, `action="suppress"`, or numeric selectors.     |
| `deny`    | Targeted deny rule. Installs pre-operation blocking logic.                                              |
| `persist` | Persistent lifetime (`lifetime="persistent"`).                                                          |
| `fixture` | Parser or ABI regression fixture. Not intended as a live telemetry recipe.                              |
| `recipe`  | Production parity document reproducing vendor configurations.                                           |

## Event Tokens

Sparse `_ESP_EVENT_TYPE` identifiers used in document naming:

| Token               | Type ID | Token               | Type ID |
| ------------------- | ------- | ------------------- | ------- |
| `thread_create`     | 1       | `thread_start`      | 2       |
| `thread_terminate`  | 3       | `process_create`    | 1000    |
| `process_terminate` | 1001    | `process_loadimage` | 1002    |
| `fo_create`         | 2000    | `fo_open`           | 2001    |
| `fo_read`           | 2002    | `fo_write`          | 2003    |
| `fo_cleanup`        | 2004    | `fs_section`        | 3000    |
| `fs_queryinfo`      | 3001    | `fs_setinfo`        | 3002    |
| `fs_security`       | 3003    | `fs_dir`            | 3004    |
| `fs_fsctl`          | 3005    | `fs_setea`          | 3006    |
| `fs_queryopen`      | 3007    | `fs_lock`           | 3008    |
| `fs_unlock`         | 3009    | `ktm_commit`        | 3010    |
| `ktm_rollback`      | 3011    | `vol_mount`         | 4000    |
| `vol_dismount`      | 4001    | `vol_fsctl`         | 4002    |
| `pipe_create`       | 5000    | `mailslot_create`   | 6000    |
| `reg_create`        | 7000    | `reg_open`          | 7001    |
| `reg_delete`        | 7002    | `reg_setvalue`      | 7003    |
| `reg_deletevalue`   | 7004    | `reg_rename`        | 7005    |
| `reg_replace`       | 7006    | `reg_restore`       | 7007    |
| `reg_setsec`        | 7008    | `reg_querykey`      | 7009    |
| `reg_queryvalue`    | 7010    | `reg_save`          | 7011    |
| `reg_load`          | 7012    | `reg_enumkey`       | 7013    |
| `reg_enumvalue`     | 7014    | `ob_create`         | 8000    |
| `ob_dup`            | 8001    | `boot_load_driver`  | 9000    |

## Bundle Tokens

Grouped event sets across multi-rule documents:

| Token                  | Contents                                                                                            |
| ---------------------- | --------------------------------------------------------------------------------------------------- |
| `create_trio`          | Empty-filter 1000 + 2000 + 7000 (`action="1"`)                                                      |
| `create_trio_action0`  | Same trio with `action="0"`                                                                         |
| `create_trio_named`    | Same trio specifying `ProcessCreate`, `FileCreate`, `fo_create`, `RegCreateKey` without `eventType` |
| `fs_ktm`               | Empty-filter 3000 through 3011                                                                      |
| `volume_set`           | Empty-filter 4000 through 4002                                                                      |
| `pipe_mailslot`        | Empty-filter 5000 + 6000                                                                            |
| `thread_handle`        | Empty-filter 1, 2, 3, 8000, 8001                                                                    |
| `process_fo_reg_mixed` | 1001, 1002, 2001, 2003, 2004, 7001, 7003, 7010                                                      |
| `reg_remainder`        | 7002, 7004 through 7014                                                                             |
| `leftover_families`    | Empty-filter 2001, 3006, plus 5000 with a pipe query                                                |

## Qualifiers

Optional last field when two documents share role, event, and filter:

`equals`, `ntpath`, `ntpath_neg`, `ntpath_ne`, `ntpath_labeled`, `pattern`, `implicit_and`, `collection`, `collection_named`, `collection_integer`, `collection_binary`, `query_process`, `query_event`, `query_fileobject`, `query_ktm`, `query_token`, `query_client`, `query_thread`, `query_file`, `query_filestream`, `query_registry`, `query_registry_key_object`, `query_pipe`, `query_mailslot`, `query_volume`, `query_disk`, `query_desktop`, `query_process_token`, `query_stream`, `type0`, `bool`, `prop17`, `deny`, `suppress`, `rewrite`, `cancel`, `queue_subrules`, `bad_eventtype`, `invalid_eventtype`, `pipe`, `named`.

| Qualifier                                 | Document Meaning                                                                                                                                 |
| ----------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------ |
| `ntpath`                                  | Minimal `$nt:` process-image equals leaf                                                                                                         |
| `ntpath_labeled`                          | Same comparand with explicit `operand`, `propertyName`, and `op`                                                                                 |
| `ntpath_neg`                              | Equals against a path that does not exist                                                                                                        |
| `ntpath_ne`                               | String comparand `2` (not-equals)                                                                                                                |
| `pattern`                                 | String comparand `3` (pattern match)                                                                                                             |
| `implicit_and`                            | Two sibling `<filter>` elements with no combinator wrapper                                                                                       |
| `named`                                   | `event=` without `eventType`                                                                                                                     |
| `type0`                                   | Empty filter written as `<filter type="0"/>`                                                                                                     |
| `collection_named`                        | String collection in `<collections>`, bound with `collection="name"`                                                                             |
| `collection_integer`, `collection_binary` | Document-owned collections of type `1` and `3`; the process-image equals leaf does not bind them                                                 |
| `query_*`                                 | Per-rule `<query>` recipe. One live leaf exists for each `SupportExportForKind` name, plus aliases `process-token`, `thread-token`, and `stream` |
| `open_missing_guid`                       | Parser-negative `open="true"` collection without `guid`                                                                                          |

## Complete Corpus Inventory (118 Documents)

The complete inventory comprises 118 XML documents: `monitor` 71, `filter` 32, `deny` 5, `enforce` 5, `fixture` 3, `persist` 1, `recipe` 1.

### Deny Family (5 Documents)

| Document File                      | Event               | Action     | Filter Definition                                                   | Installs?                                      | Enforces?                                                            |
| ---------------------------------- | ------------------- | ---------- | ------------------------------------------------------------------- | ---------------------------------------------- | -------------------------------------------------------------------- |
| `deny_file_create.xml`             | FoCreate 2000       | `deny`     | fileobject p1 equals `$nt:C:\tools\esptool-deny\file_target.txt`    | Yes (native)                                   | Yes (native file blocking, returns `STATUS_NOT_FOUND`)               |
| `deny_fo_open_fileobject_deny.xml` | FoOpen 2001         | `deny`     | fileobject p1 equals `$nt:C:\tools\esptool-deny\fo_open_target.txt` | Yes (with `--enforce-compat`)                  | Yes (with `--enforce-compat`, open returns `STATUS_NOT_FOUND`)       |
| `deny_process_create.xml`          | ProcessCreate 1000  | `deny`     | process p1 equals `$nt:C:\tools\esptool-deny\proc_target.exe`       | Yes (with `--enforce-compat`)                  | Yes (with `--enforce-compat`, process creation returns `0x80004005`) |
| `deny_registry_create.xml`         | RegCreateKey 7000   | `suppress` | registry_key p1 equals `esptool_deny_reg`                           | Yes                                            | No (RegCreateKey lacks callback disposition mapping)                 |
| `deny_registry_object.xml`         | ObCreateHandle 8000 | `deny`     | desktop p1 pattern `*esptool_deny_reg*`                             | No (`SupportsEnforcePayload` false, mask 0x19) | No                                                                   |

### Enforce Family (5 Documents)

| Document File                                     | Event | Action       | Notes                                                                                        |
| ------------------------------------------------- | ----- | ------------ | -------------------------------------------------------------------------------------------- |
| `enforce_fo_create_fileobject_deny.xml`           | 2000  | `deny`       | Native FoCreate deny; fileobject equals `$nt:C:\tools\esptool-gap\deny_create.txt`           |
| `enforce_fo_create_empty_rewrite.xml`             | 2000  | `5`          | Empty-filter rewrite selector                                                                |
| `enforce_fo_create_empty_cancel.xml`              | 2000  | `6`          | Empty-filter cancel selector                                                                 |
| `enforce_process_create_empty_queue_subrules.xml` | 1000  | `1` then `7` | Queue-backed notify plus match-subrules against that predecessor rule                        |
| `enforce_process_create_process_deny.xml`         | 1000  | `suppress`   | Historical name. Selector 4; child process starts. Working deny is `deny_process_create.xml` |

### Persist and Recipe Documents (2 Documents)

| Document File                                                | Event       | Action                              | Notes                                                                                             |
| ------------------------------------------------------------ | ----------- | ----------------------------------- | ------------------------------------------------------------------------------------------------- |
| `persist_process_create_empty_deny.xml`                      | 1000        | `suppress`, `lifetime="persistent"` | Historical name. Selector 4, no queue. Persistent deny on 1000 requires `--enforce-compat`        |
| `recipe_mprtp_pipe_create_empty_fo_open_fileobject_pipe.xml` | 5000 + 2001 | `1`                                 | MpRtp 26080 ABI: empty PipeCreate plus FoOpen fileobject type 28 equals 3 (pipe). Altitude 328000 |

### Regression and Parser Negative Fixtures (3 Documents)

| Document File                                      | Parser Outcome                           | Purpose                                                                                                          |
| -------------------------------------------------- | ---------------------------------------- | ---------------------------------------------------------------------------------------------------------------- |
| `fixture_process_create_process_bad_eventtype.xml` | Fails (`rule eventType is not a number`) | Tests parser rejection of non-numeric event types (`eventType="not-a-number"`)                                   |
| `fixture_collection_open_missing_guid.xml`         | Fails (`open="true" requires guid`)      | Tests collection validation (`<collection open="true"/>` without `guid`)                                         |
| `fixture_combinator_invalid_eventtype.xml`         | Succeeds (AST validation only)           | Exercises combinators (`<and>`, `<or>`, `<not>`) and labeled filters with non-sparse event types `12`, `30`, `1` |

### Filter Documents (32 Documents)

All filter documents use queue-backed Action 1 (`action="1"`):

| Document File                                          | Event Type       | Filter Predicate Definition                                                    |
| ------------------------------------------------------ | ---------------- | ------------------------------------------------------------------------------ |
| `filter_fo_create_file.xml`                            | 2000             | file p17 pattern `*`                                                           |
| `filter_fo_create_file_prop17.xml`                     | 2000             | file p17 pattern `*esptool_prop17.txt`                                         |
| `filter_fo_create_fileobject_equals.xml`               | 2000             | fileobject p1 equals `REPLACE_FO_EQUALS`                                       |
| `filter_fo_create_filestream.xml`                      | 2000             | filestream p1 pattern `*`                                                      |
| `filter_ktm_commit_ktm.xml`                            | 3010             | ktm p2 numeric 0                                                               |
| `filter_mailslot_create_mailslot.xml`                  | 6000             | mailslot p1 pattern `*esptool_gap*`                                            |
| `filter_multi_process_or_registry_key_not_process.xml` | 1000, 7000, 1000 | process equals `cmd.exe`; `or` of two registry keys; `not` process `csrss.exe` |
| `filter_ob_create_desktop.xml`                         | 8000             | desktop p1 pattern `*`                                                         |
| `filter_pipe_create_pipe.xml`                          | 5000             | pipe p1 pattern `*esptool_gap*`                                                |
| `filter_process_create_and_process.xml`                | 1000             | `and` process `$nt:...cmd.exe` plus client bool 1                              |
| `filter_process_create_client_bool.xml`                | 1000             | client p1 bool 1                                                               |
| `filter_process_create_event.xml`                      | 1000             | event p2 numeric 1000                                                          |
| `filter_process_create_event_bool.xml`                 | 1000             | event p1 bool 1                                                                |
| `filter_process_create_not_process.xml`                | 1000             | `not` process p1 equals `csrss.exe`                                            |
| `filter_process_create_process_collection.xml`         | 1000             | process p1 comparand 4, inline `$nt:` cmd.exe string collection                |
| `filter_process_create_process_collection_binary.xml`  | 1000             | process equals cmd.exe; binary collection `esp-bytes` created, not bound       |
| `filter_process_create_process_collection_integer.xml` | 1000             | process equals cmd.exe; integer collection `token-levels` created, not bound   |
| `filter_process_create_process_collection_named.xml`   | 1000             | process p1 comparand 4 bound to named collection `cmd-images`                  |
| `filter_process_create_process_implicit_and.xml`       | 1000             | sibling process equals + client bool (implicit And)                            |
| `filter_process_create_process_ntpath.xml`             | 1000             | process p1 equals `$nt:C:\Windows\System32\cmd.exe`                            |
| `filter_process_create_process_ntpath_labeled.xml`     | 1000             | same leaf with `propertyName="imagePath"` `op="equals"`                        |
| `filter_process_create_process_ntpath_ne.xml`          | 1000             | process p1 not-equals `$nt:C:\Windows\System32\zzz_no_such.exe`                |
| `filter_process_create_process_ntpath_neg.xml`         | 1000             | process p1 equals a path that does not exist                                   |
| `filter_process_create_process_pattern.xml`            | 1000             | process p1 pattern `*cmd.exe`                                                  |
| `filter_process_create_token.xml`                      | 1000             | token p3 numeric 0                                                             |
| `filter_process_create_xor_process.xml`                | 1000             | `xor` cmd.exe vs notepad.exe NT paths                                          |
| `filter_reg_create_or_registry_key.xml`                | 7000             | `or` of two registry_key equals leaves                                         |
| `filter_reg_create_registry_key_ntpath.xml`            | 7000             | registry_key p1 equals `\REGISTRY\MACHINE\SOFTWARE\esptool_gap_probe`          |
| `filter_reg_delete_registry_key_object.xml`            | 7002             | registry_key_object p1 bool 1                                                  |
| `filter_thread_create_thread.xml`                      | 1                | thread p1 numeric 0                                                            |
| `filter_vol_fsctl_disk.xml`                            | 4002             | disk p1 pattern `*`                                                            |
| `filter_vol_fsctl_volume.xml`                          | 4002             | volume p1 pattern `*`                                                          |

### Single-Event Empty-Filter Monitor Documents (43 Documents)

All single-event monitor documents configure empty filters (`action="0"` or `action="1"`):

| Document File                   | Event Type | Document File                      | Event Type                  |
| ------------------------------- | ---------- | ---------------------------------- | --------------------------- |
| `monitor_boot_load_driver.xml`  | 9000       | `monitor_file_create_notify.xml`   | 2000 (`action="0"`)         |
| `monitor_fo_cleanup.xml`        | 2004       | `monitor_fo_create.xml`            | 2000                        |
| `monitor_fo_open.xml`           | 2001       | `monitor_fo_read.xml`              | 2002                        |
| `monitor_fo_write.xml`          | 2003       | `monitor_fs_dir.xml`               | 3004                        |
| `monitor_fs_fsctl.xml`          | 3005       | `monitor_fs_lock.xml`              | 3008                        |
| `monitor_fs_queryinfo.xml`      | 3001       | `monitor_fs_queryopen.xml`         | 3007                        |
| `monitor_fs_section.xml`        | 3000       | `monitor_fs_security.xml`          | 3003                        |
| `monitor_fs_setea.xml`          | 3006       | `monitor_fs_setinfo.xml`           | 3002                        |
| `monitor_fs_unlock.xml`         | 3009       | `monitor_ktm_commit.xml`           | 3010                        |
| `monitor_ktm_rollback.xml`      | 3011       | `monitor_ob_dup.xml`               | 8001                        |
| `monitor_process_create.xml`    | 1000       | `monitor_process_create_type0.xml` | 1000 (`<filter type="0"/>`) |
| `monitor_process_loadimage.xml` | 1002       | `monitor_process_terminate.xml`    | 1001                        |
| `monitor_reg_create.xml`        | 7000       | `monitor_reg_delete.xml`           | 7002                        |
| `monitor_reg_deletevalue.xml`   | 7004       | `monitor_reg_enumkey.xml`          | 7013                        |
| `monitor_reg_enumvalue.xml`     | 7014       | `monitor_reg_load.xml`             | 7012                        |
| `monitor_reg_open.xml`          | 7001       | `monitor_reg_querykey.xml`         | 7009                        |
| `monitor_reg_queryvalue.xml`    | 7010       | `monitor_reg_rename.xml`           | 7005                        |
| `monitor_reg_replace.xml`       | 7006       | `monitor_reg_restore.xml`          | 7007                        |
| `monitor_reg_save.xml`          | 7011       | `monitor_reg_setsec.xml`           | 7008                        |
| `monitor_reg_setvalue.xml`      | 7003       | `monitor_thread_start.xml`         | 2                           |
| `monitor_thread_terminate.xml`  | 3          | `monitor_vol_dismount.xml`         | 4001                        |
| `monitor_vol_mount.xml`         | 4000       |                                    |                             |

### Query Recipe Monitor Documents (18 Documents)

Configures empty filters with post-notification `<query>` recipes:

| Document File                                      | Event Type | Query Kind                        | Properties / Context Mode                                    |
| -------------------------------------------------- | ---------- | --------------------------------- | ------------------------------------------------------------ |
| `monitor_fo_create_query_file.xml`                 | 2000       | `file`                            | `properties="17"`                                            |
| `monitor_fo_create_query_fileobject.xml`           | 2000       | `fileobject`                      | `properties="9"`, `context="set,enum"`                       |
| `monitor_fo_create_query_filestream.xml`           | 2000       | `filestream`                      | `properties="1"`                                             |
| `monitor_fo_create_query_stream.xml`               | 2000       | `stream` (alias for `filestream`) | `properties="1"`                                             |
| `monitor_ktm_commit_query_ktm.xml`                 | 3010       | `ktm`                             | `properties="1"`                                             |
| `monitor_mailslot_create_query_mailslot.xml`       | 6000       | `mailslot`                        | `properties="1"`                                             |
| `monitor_ob_create_query_desktop.xml`              | 8000       | `desktop`                         | `properties="1"`                                             |
| `monitor_pipe_create_query_pipe.xml`               | 5000       | `pipe`                            | `properties="1"`                                             |
| `monitor_process_create_query_client.xml`          | 1000       | `client`                          | `properties="1"`                                             |
| `monitor_process_create_query_event.xml`           | 1000       | `event`                           | `properties="1"`                                             |
| `monitor_process_create_query_process.xml`         | 1000       | `process`, `event`                | `properties="6,13,2"`, second query `event` `properties="1"` |
| `monitor_process_create_query_process_token.xml`   | 1000       | `process-token`, `thread-token`   | `properties="3"` on both queries                             |
| `monitor_process_create_query_token.xml`           | 1000       | `token`                           | `properties="3"`                                             |
| `monitor_reg_create_query_registry.xml`            | 7000       | `registry`                        | `properties="1"`                                             |
| `monitor_reg_delete_query_registry_key_object.xml` | 7002       | `registry-key-object`             | `properties="1"`                                             |
| `monitor_thread_start_query_thread.xml`            | 2          | `thread`                          | `properties="1"`                                             |
| `monitor_vol_fsctl_query_disk.xml`                 | 4002       | `disk`                            | `properties="1"`                                             |
| `monitor_vol_fsctl_query_volume.xml`               | 4002       | `volume`                          | `properties="1"`                                             |

### Multi-Event Bundle Monitor Documents (10 Documents)

Configures grouped sets of empty-filter rules across multiple event types:

| Document File                      | Event Types Covered                            | Description                                                                                         |
| ---------------------------------- | ---------------------------------------------- | --------------------------------------------------------------------------------------------------- |
| `monitor_create_trio.xml`          | 1000, 2000, 7000                               | Empty-filter ProcessCreate, FoCreate, RegCreateKey (`action="1"`)                                   |
| `monitor_create_trio_action0.xml`  | 1000, 2000, 7000                               | Same trio with `action="0"` (resolves to Selector 1)                                                |
| `monitor_create_trio_named.xml`    | 1000, 2000, 2000, 7000                         | Same trio specifying `ProcessCreate`, `FileCreate`, `fo_create`, `RegCreateKey` without `eventType` |
| `monitor_fs_ktm.xml`               | 3000 through 3011                              | Comprehensive filesystem and KTM event bundle                                                       |
| `monitor_volume_set.xml`           | 4000 through 4002                              | Volume mount, dismount, and FSCTL bundle                                                            |
| `monitor_pipe_mailslot.xml`        | 5000, 6000                                     | Named Pipe and Mailslot creation bundle                                                             |
| `monitor_thread_handle.xml`        | 1, 2, 3, 8000, 8001                            | Thread creation/start/termination and Object Manager handle bundle                                  |
| `monitor_process_fo_reg_mixed.xml` | 1001, 1002, 2001, 2003, 2004, 7001, 7003, 7010 | Mixed process, file, and registry lifecycle bundle                                                  |
| `monitor_reg_remainder.xml`        | 7002, 7004 through 7014                        | Comprehensive registry operation bundle                                                             |
| `monitor_leftover_families.xml`    | 2001, 3006, 5000                               | Empty FoOpen (2001) and FsSetEa (3006) plus PipeCreate (5000) with pipe query                       |

# Event Configuration Attachment Rules

`AttachFilterToDescriptor` in `esp/EspRuleInstall.cpp` attaches subsystem-specific configuration buffers (`FoIoConfigBlob`) to the rule descriptor at offset `+96` based on event type:

| Event Type Range              | Attached Configuration Blob                                 | Filter Pointer Placement                                                                                                                                                                                                                                                                          |
| ----------------------------- | ----------------------------------------------------------- | ------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------------- |
| `2000` through `2004`, `5000` | Typed FoIo Configuration (`kRuleEventConfigPtrOffset = 96`) | When the filter tree contains a FileObject leaf and the event is FoIo (`2000` through `2004`), the FileObject filter handle is written to FoIo filter offset `+936` (`kFoIoFileObjectFilterOffset`). If a process filter leaf is present, its handle is written to rule descriptor offset `+688`. |
| `1000`                        | ProcessCreate Configuration                                 | ProcessCreate configuration blob is unconditionally attached to descriptor offset `+96`. When a top-level process image filter leaf is present (`fo.kind == Leaf`), it is rewritten as a FileObject filter (default property 1) at the image-load FileObject offset (`+400`).                     |
| `1`, `2`, `3`                 | Thread Configuration                                        | Thread configuration blob attached to descriptor offset `+96`. Filter handle stored at `ProcessConfig + 8` via `AttachThreadConfig`.                                                                                                                                                              |
| `1001`                        | Process Configuration                                       | Process configuration blob attached to descriptor offset `+96`. Filter handle stored at `ProcessConfig + 8`.                                                                                                                                                                                      |
| `1002`                        | Image-Load Configuration                                    | Image-load configuration blob attached to descriptor offset `+96`. FileObject filter leaf stored at offset `+400`; otherwise process filter stored at offset `+8`.                                                                                                                                |
| `7000` through `7014`         | Registry Configuration                                      | Registry configuration blob attached to descriptor offset `+96`. Filter handle stored at `RegistryConfig + 8`.                                                                                                                                                                                    |
| Other Events                  | Rule Descriptor Direct Placement                            | Process constructor filter handle stored at offset `+688`; event constructor filter handle stored at offset `+40`.                                                                                                                                                                                |

For Named Pipe creation (`5000`), `RestrictPipeTarget` additionally sets the FoIo target type to Pipe (`kFoTargetPipe = 3`).

# Authoring Guidelines for New Rule Documents

When creating new rule documents for `tools/esptool/rules/`:

1. File naming: Adhere strictly to the naming grammar: `{role}_{event}_{filter}[_{qualifier}].xml`.
2. Client specification: Always include `<client name="..." altitude="..."/>` with a unique name and altitude to prevent port registration collisions during concurrent testing.
3. Event identification: Set `eventType` to a sparse ABI integer from `esp/EspEventIds.h`. Do not omit `eventType` unless testing the parser alias resolution for `ProcessCreate`, `FileCreate`/`fo_create`, or `RegCreateKey`.
4. Action specification: Use `action="deny"` for real-time enforcement rules (Selector 5). Use `action="suppress"` for telemetry suppression (Selector 4). Raw `action="4"` is permitted but discouraged.
5. Disposition: For enforcing rules (`action="deny"`), specify `disposition="not_found"`, `disposition="access_denied"`, or `disposition="virus"`.
6. Enforce compatibility: If authoring a deny rule for an event other than FoCreate (`2000`), remember that running the rule requires passing the `--enforce-compat` flag to `esptool`.
7. Manifest registration: Register any newly created XML document in `smoke/rules.manifest.json` and cite it in this document before referencing it in automated test suites.
