# Windows Endpoint Security Platform (WESP) Research

This project is an ongoing exploration of the Windows Endpoint Security Platform (WESP, or ESP), introduced in Windows 11 Insider Preview builds (25H2, builds 10.0.29641 to 10.0.29667). WESP changes how Windows handles endpoint security by shifting away from traditional, synchronous minifilter round-trips toward in-kernel decision graphs and decoupled asynchronous telemetry.

Using AI-assisted reverse engineering, the full platform stack has been analyzed and documented across user and kernel space:

- `wesp.sys`: The core filesystem minifilter driver, executive callbacks, and in-kernel decision engine.
- `espclient.dll`: The user-mode client library, export catalog, and BDD compilation pipeline.
- `wesp_elam.sys`: The early-boot sensor and shared telemetry staging queue.

To explore and test these internals firsthand, the repository includes `esptool`, a standalone C++20 research harness, accompanied by a test corpus of 118 XML rule documents to exercise the platform's APIs, event types, and enforcement gates.

# Documentation Index

The technical findings, specifications, and tooling are documented across three core references:

- [WESP Reverse-Engineered Architecture and Technical Reference](docs/wesp_re_tech_reference.md): Detailed reverse engineering analysis of the kernel driver architecture (`wesp.sys`), Filter Manager communication port wire protocols, the in-kernel Reduced Ordered Binary Decision Diagram (ROBDD) evaluation engine, disposition tables, security gates, and early-boot synchronization (`wesp_elam.sys`).
- [Esptool Architectural Reference](docs/esptool_tech_reference.md): Complete technical reference for the research harness, detailing operational planes, the 36-command execution reference with parameter arities and sequences, live diagnostic scenarios, trust scaffolding, and the automated smoke test runner.
- [Esptool Declarative XML Rule Specification and Reference](rules/README.md): Full specification for esptool's declarative XML rule format, test fixtures, and XmlLite parser. Covers the XML grammar, 47-item error catalog, element schemas, action selectors, kernel disposition codes, relational and numeric operators 1 through 11, complete 15-family property catalogs, and the 118-document test corpus.

# What is WESP?

In traditional Windows endpoint security, third-party filesystem minifilter drivers pair with user-mode service daemons. When an I/O request occurs (such as an `NtCreateFile` call), the minifilter intercepts the request in a pre-operation callback, calls `FltSendMessage`, and suspends the calling application thread while waiting for the user-mode service to return an authorization verdict via `FilterReplyMessage`.

This synchronous design causes latency spikes on I/O paths, introduces deadlock risks during memory-mapped paging operations, and leaves host responsiveness vulnerable to service hangs or crashes.

WESP eliminates synchronous user-mode round-trips through an asymmetric architecture: user space compiles detection rules into binary decision graphs, and the kernel evaluates them directly during pre-operation callbacks.

The architecture operates across three functional planes:

- **Control Plane**: Operates over the Filter Manager communication port `\EspFilterPort`. It authenticates security agents, manages sessions and client registrations, and transmits pre-compiled rule sets from user space into the kernel.
- **Data Plane**: Intercepts operations across five kernel subsystems (Process Manager, Object Manager, Configuration Manager, Filter Manager, and Kernel Transaction Manager) across 47 event types. The kernel driver (`wesp.sys`) evaluates rules directly within pre-operation callbacks. If an enforcing rule matches, the callback returns an immediate blocking status (`FLT_PREOP_COMPLETE` with `STATUS_NOT_FOUND`, or `PS_CREATE_NOTIFY_INFO.CreationStatus` denial) before the I/O ever reaches the filesystem or process manager.
- **Telemetry Plane**: Mediates non-blocking event transfer. For observation rules, the driver enqueues event envelopes into memory-budgeted kernel queues. User-mode listeners retrieve events asynchronously through overlapped reads without suspending monitored applications. Telemetry completion calls serve only as memory quota releases rather than synchronous authorization replies.

For complete architectural diagrams, callback listings, and wire protocol details, see [docs/wesp_re_tech_reference.md](docs/wesp_re_tech_reference.md).

# Repository Layout

| Directory / File | Contents                                                                                 |
| ---------------- | ---------------------------------------------------------------------------------------- |
| `docs/`          | Comprehensive technical references for WESP kernel architecture and `esptool`.           |
| `esptool/`       | Source code and Visual Studio solution for the C++20 research harness.                   |
| `rules/`         | Corpus of 118 declarative XML test rule documents used by `esptool`.                     |
| `smoke/`         | Automated PowerShell test runner (`Run-EsptoolSmoke.ps1`) covering 312 smoke test cases. |

# Installation and Environment Setup

## Building esptool

The harness is written in C++20 and targets x64 Windows. Build the project using Visual Studio 2022 or MSBuild:

```cmd
msbuild esptool\esptool.vcxproj -p:Configuration=Release -p:Platform=x64
```

Build specifications:

- **Platform**: x64 only.
- **Language Standard**: ISO C++20 (`/std:c++20`).
- **Compiler Flags**: `/W4 /WX /guard:cf /permissive-`.
- **Runtime Library**: Statically linked CRT (`/MT` for Release, `/MTd` for Debug) ensuring the binary has no external dependencies on `vcruntime140.dll` or `msvcp140.dll`.
- **SDK Dependencies**: `XmlLite.lib`, `Shlwapi.lib`, `Bcrypt.lib`.
- **Output Artifact**: `esptool\x64\Release\esptool.exe`.

## Target Machine Setup

WESP components ship in Windows 11 Insider Preview builds (such as builds 10.0.29641 to 10.0.29667). To prepare a virtual machine for research:

1. Enable test signing and reboot:
   ```cmd
   bcdedit /set {current} testsigning on
   shutdown /r /t 0
   ```
2. Verify that test signing is active:
   ```cmd
   bcdedit /enum {current}
   ```
3. Load the WESP minifilter driver:
   ```cmd
   fltmc load wesp
   ```
4. Verify that the filter is running at altitude `329500`:
   ```cmd
   fltmc filters
   ```

# Research Workflows with esptool

The `esptool` harness and its accompanying XML rule corpus enable hands-on validation of the WESP subsystem across its control, data, and telemetry planes. Execute these workflows from an elevated PowerShell prompt within the directory containing `esptool.exe` and `rules\` (or the repository root).

Operational notes:

- **Automatic test-signing adaptation**: In standard test-signed lab environments where `esptool` runs without an AM-PPL signature, the tool automatically detects the environment and bypasses token attribute stamping. Manual `--no-provision` flags are optional. To disable auto-detection and restore traditional behavior, pass `--no-auto-provision`.
- **Selective worker hopping**: Commands that interact with the driver hop to a same-image child worker running as `NT AUTHORITY\SYSTEM` with `SeTcbPrivilege` only when token stamping or cleanup is required, or when forced via `--force-hop`. When running directly as a worker, `--worker` suppresses further hops.
- **Diagnostic tracing**: Diagnostic tracing is enabled by appending `--log <path>` combined with `--verbose`.
- **Event delivery mechanism**: Asynchronous notification retrieval defaults to completion callbacks; supply `--iocp` to pump notifications via `EspConnectEventQueueWithIocp`.

## Sanity Check: DLL and Trust State

Verify that `espclient.dll` loads, confirm export resolution, and inspect the PPL protection byte and `WESP://Permission` token security attribute:

```powershell
esptool.exe status
esptool.exe exports
```

Execution breakdown:

- `esptool.exe status` displays the loaded DLL path, total export resolution count (120 of 121), process elevation, TCB privilege presence, token attribute state, and system code integrity policy:
  ```text
  dll: espclient.dll
  resolved 120 of 121
  account: SYSTEM
  elevated: yes
  tcb: enabled
  protection: 0x00 (None, None, audit=0)
  attribute: absent (query 0x00000000)
  codeintegrity: options=0x00280303 testsigning=on ci=on
  secureboot: off
  ```
- `esptool.exe exports` lists all 121 cataloged exports, their parameter arities, and whether `GetProcAddress` succeeded. On reference builds, 120 exports resolve successfully (`_DllMainCRTStartup` is cataloged but unresolved).

## Live Monitor: Any Process Creation

Deploy a queue-backed rule to capture all process creation activity system-wide without applying filtering predicates. Under test-signing environments, `esptool` automatically enables un-provisioned mode:

```powershell
esptool.exe monitor --rules rules\monitor_process_create.xml --duration 10000 --max 10
```

Rule specification (`rules\monitor_process_create.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-mon-proc" altitude="385000"/>
  <rules>
    <rule name="process-create" event="ProcessCreate" eventType="1000"
          lifetime="transient" action="0"/>
  </rules>
</esptool>
```

Testing and verification:

1. In a second PowerShell window, launch an application while the monitor pumps:
   ```powershell
   notepad.exe
   ```
2. The primary console receives the decoded notification with all process properties:
   ```text
   [INFO ] auto-provision: test-signing active on non-PPL process; automatic --no-provision selected
   [INFO ] monitor: rules installed, pumping
   [INFO ] notification 1 id=1 kind=3277015211 payload=0 event=1000 pid=4812 tid=0 name=\Device\HarddiskVolume3\Windows\System32\notepad.exe
     prop[Process:6] (ProcessId, type 5): 4812 (0x12CC)
     prop[Process:20] (ImagePath, type 8): \Device\HarddiskVolume3\Windows\System32\notepad.exe
     prop[Process:1] (CommandLine, type 8): "C:\Windows\System32\notepad.exe"
     prop[Process:2] (SessionId, type 10): 0x1DD455AE1AADB2C
   [INFO ] notification pump received 1
   received 1 notifications
   ```
3. Exit code behavior: The command exits with code `0` only if at least one notification arrives within the duration window. If zero notifications arrive, the command exits with code `1`.

## Filtered Monitor: Targeted Process Matching

Deploy a rule configured with an `EspCreateProcessFilter` predicate to isolate execution of `cmd.exe` while ignoring other processes:

```powershell
esptool.exe monitor --rules rules\filter_process_create_process_ntpath.xml --duration 15000 --max 5
```

Rule specification (`rules\filter_process_create_process_ntpath.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-filt-ntpath" altitude="410000"/>
  <rules>
    <rule name="proc-nt-cmd" event="ProcessCreate" eventType="1000"
          lifetime="transient" action="1">
      <filter type="10" comparand="1" property="1"
              value="$nt:C:\Windows\System32\cmd.exe"/>
    </rule>
  </rules>
</esptool>
```

Filter mechanics:

- `filter type="10"` invokes `EspCreateProcessFilter`.
- `property="1"` selects the process image path.
- `comparand="1"` enforces an exact string equality comparison.
- Value `$nt:C:\Windows\System32\cmd.exe` is automatically expanded to the NT device namespace path (`\Device\HarddiskVolumeN\Windows\System32\cmd.exe`).

Testing and verification:

1. In a second window, launch `notepad.exe`:
   ```powershell
   notepad.exe
   ```
   No notification arrives; the monitor remains silent.
2. In the second window, launch `cmd.exe`:
   ```powershell
   cmd.exe /c echo test
   ```
   A matching `event=1000` notification is captured and decoded immediately.

## Named Pipe Monitor: Browser and Programmatic IPC Triggers

Deploy a queue-backed rule to capture Named Pipe creation (`PIPE_CREATE` / `5000`). Unlike process creation telemetry, the kernel Named Pipe callback fully populates the process property bag (`pid`), thread property bag (`tid`), and FileObject name bag (`name`):

```powershell
esptool.exe monitor --rules rules\monitor_pipe_mailslot.xml --duration 20000 --max 10
```

Rule specification (`rules\monitor_pipe_mailslot.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-ipcobj" altitude="385000"/>
  <rules>
    <rule name="pipe-create" event="PipeCreate" eventType="5000"
          lifetime="transient" action="0"/>
    <rule name="mailslot-create" event="MailslotCreate" eventType="6000"
          lifetime="transient" action="0"/>
  </rules>
</esptool>
```

Testing and verification:

1. Method A (Browser IPC Trigger): Launch a Chromium-based browser such as Microsoft Edge or Google Chrome. Modern multi-process browsers establish Windows Named Pipes immediately upon startup for Mojo IPC broker communication (`\Device\NamedPipe\mojo.*`) and crash reporting (`\Device\NamedPipe\crashpad_*`):
   ```powershell
   Start-Process msedge.exe -ArgumentList "about:blank"
   ```
2. Method B (Programmatic PowerShell Trigger): To create a deterministic, isolated Named Pipe server stream without launching external applications:
   ```powershell
   $pipe = [System.IO.Pipes.NamedPipeServerStream]::new('esptool-live-pipe', [System.IO.Pipes.PipeDirection]::InOut, 1)
   $pipe.Dispose()
   ```
3. Decoded notification output:
   ```text
   [INFO ] auto-provision: test-signing active on non-PPL process; automatic --no-provision selected
   [INFO ] monitor: rules installed, pumping
   [INFO ] notification 1 id=1 kind=1014787250 payload=0 event=5000 pid=4812 tid=6412 name=\Device\NamedPipe\mojo.4812.5120.12847102948102
     prop[Process:6] (ProcessId, type 5): 4812 (0x12CC)
     prop[Process:20] (ImagePath, type 8): \Device\HarddiskVolume3\Program Files (x86)\Microsoft\Edge\Application\msedge.exe
     prop[Process:1] (CommandLine, type 8): "C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe" --single-argument about:blank
     prop[Process:2] (SessionId, type 10): 0x1DD4552F1242DBD
     prop[Thread:1] (ThreadId, type 5): 6412 (0x190C)
     prop[Pipe:1] (PipeName, type 8): \Device\NamedPipe\mojo.4812.5120.12847102948102
   [INFO ] notification 2 id=2 kind=1014787250 payload=0 event=5000 pid=6124 tid=6128 name=\Device\NamedPipe\esptool-live-pipe
     prop[Process:6] (ProcessId, type 5): 6124 (0x17EC)
     prop[Process:20] (ImagePath, type 8): \Device\HarddiskVolume3\Windows\System32\WindowsPowerShell\v1.0\powershell.exe
     prop[Pipe:1] (PipeName, type 8): \Device\NamedPipe\esptool-live-pipe
   [INFO ] notification pump received 2
   received 2 notifications
   ```
   Field analysis:
   - `event=5000`: Sparse identifier for `PIPE_CREATE`.
   - `pid` and `tid`: Populated from the process and thread property bags at parameter block offsets `+16` and `+8`.
   - `name`: Populated from the FileObject property bag as a boxed `UNICODE_STRING` (type `8`), displaying the full NT device namespace pipe path.

## Native Deny: Block File Path

Deploy an enforcing rule to prevent file creation at a specific path. This enforcement path requires no binary modifications and operates natively on unmodified builds:

```powershell
esptool.exe rules --rules rules\deny_file_create.xml --duration 15000
```

Rule specification (`rules\deny_file_create.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-deny-file" altitude="820300"/>
  <rules>
    <rule name="deny-file-create" event="FoCreate" eventType="2000"
          lifetime="transient" action="deny">
      <filter type="6" comparand="1" property="1"
              value="$nt:C:\tools\esptool-deny\file_target.txt"/>
    </rule>
  </rules>
</esptool>
```

Testing and verification:

1. While `esptool` prints `rules-hold 15000`, attempt to create the target file in a second window:
   - In `cmd.exe`:
     ```cmd
     echo a > C:\tools\esptool-deny\file_target.txt
     ```
     The operation fails with:
     ```text
     Element not found.
     ```
   - In PowerShell:
     ```powershell
     New-Item C:\tools\esptool-deny\file_target.txt -ItemType File
     ```
     The operation fails with `The system cannot find the file specified` (`STATUS_NOT_FOUND` / `0xC0000225` / Win32 `1168` `ERROR_NOT_FOUND`). Filter Manager returns `FLT_PREOP_COMPLETE` during pre-create, blocking the IRP before it reaches the filesystem driver.
2. Attempt to create a file with a non-matching name:
   ```powershell
   New-Item C:\tools\esptool-deny\other_file.txt -ItemType File
   ```
   The creation succeeds normally.

### Returning Access is Denied (Custom Enforcing Dispositions)

By default, an enforcing deny rule on `FoCreate` (`2000`) selects disposition slot 2 in the kernel driver's Filesystem/KTM disposition table, completing pre-create with `STATUS_NOT_FOUND` (`0xC0000225`).

To return `Access is denied.` (`STATUS_ACCESS_DENIED` / `0xC0000022` / Win32 error `5`) instead, specify `disposition="access_denied"` (or `disposition="denied"`, or numeric `modifyKind="2"`) on the `<rule>` element:

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-deny-file" altitude="820300"/>
  <rules>
    <rule name="deny-file-create" event="FoCreate" eventType="2000"
          lifetime="transient" action="deny" disposition="access_denied">
      <filter type="6" comparand="1" property="1"
              value="$nt:C:\tools\esptool-deny\file_target.txt"/>
    </rule>
  </rules>
</esptool>
```

Testing with `disposition="access_denied"`:

```cmd
C:\tools\esptool-deny>echo a > file_target.txt
Access is denied.
```

Supported `disposition` values across the kernel Filesystem/KTM disposition table:

- `disposition="access_denied"` (or `modifyKind="2"`): Slot 1 maps to `STATUS_ACCESS_DENIED` (`0xC0000022` / `Access is denied.`).
- `disposition="not_found"` (default, or `modifyKind="3"`): Slot 2 maps to `STATUS_NOT_FOUND` (`0xC0000225` / `Element not found.` / `The system cannot find the file specified.`).
- `disposition="virus"` (or `modifyKind="1"`): Slot 0 maps to `STATUS_VIRUS_INFECTED` (`0xC0000906` / `Operation did not complete successfully because the file contains a virus or potentially unwanted software.`).

## Compatibility Deny: Block Process Execution

Deploy an enforcing rule to block process execution by path. Because an unmodified `espclient.dll` refuses the enforcing descriptor for `PROCESS_CREATE` (1000), this workflow requires the `--enforce-compat` in-memory patch:

```powershell
esptool.exe rules --rules rules\deny_process_create.xml --enforce-compat --duration 20000
```

Rule specification (`rules\deny_process_create.xml`):

```xml
<?xml version="1.0" encoding="utf-8"?>
<esptool>
  <client name="esptool-deny-proc" altitude="820330"/>
  <rules>
    <rule name="deny-process-create" event="ProcessCreate" eventType="1000"
          lifetime="transient" action="deny">
      <filter type="10" comparand="1" property="1"
              value="$nt:C:\tools\esptool-deny\proc_target.exe"/>
    </rule>
  </rules>
</esptool>
```

Testing and verification:

1. `esptool` logs the patch confirmation and holds the session active:
   ```text
   [INFO ] auto-provision: test-signing active on non-PPL process; automatic --no-provision selected
   [WARN ] enforce-compat: rule 'deny-process-create' installed via in-memory client patch; confirm live denial with canary trigger
   rules-hold 20000
   ```
2. While the rule holds, attempt to execute `proc_target.exe` in a second window:
   ```powershell
   Start-Process C:\tools\esptool-deny\proc_target.exe
   ```
   The process launch fails with `Element not found.` (`STATUS_NOT_FOUND` / `0xC0000225` / Win32 `1168` `ERROR_NOT_FOUND`). The kernel driver process creation callback writes this status directly into `PS_CREATE_NOTIFY_INFO.CreationStatus`, aborting initialization before user-mode code executes.
3. Launching any other executable image proceeds without interference.

## Live Kernel Object References: Minting and Inspection

WESP exposes an object reference subsystem allowing security clients to obtain kernel object handles across intercepted executive entities (`process`, `file`, `registry`, `thread`, `desktop`, `token`), inspect runtime identity metadata, and query property buffers:

```powershell
esptool.exe refs process --pid self --properties 6,20,1,2
esptool.exe refs file --path C:\Windows\System32\ntdll.dll --properties 1,6
esptool.exe refs registry --path HKLM\Software --properties 1,2
```

Internal execution sequence:

1. `esptool` connects to `\EspFilterPort` and invokes the subsystem-specific reference constructor (`EspCreateProcessReference`, `EspCreateFileReferenceByPath`, or `EspCreateRegistryKeyReference`).
2. The driver returns an opaque reference handle. `esptool` calls `EspGetEventObjectFromReference` to unwrap the internal event object view.
3. `EspGetEventObjectType` returns the executive object type code (`2` for Process, `3` for File, `8` for Registry Key).
4. `EspGetEventObjectId` returns the unique kernel-assigned 64-bit object identifier.
5. If `--properties` is specified, `esptool` allocates memory and calls the corresponding query export (`EspQueryProcessProperties` or `EspQueryRegistryKeyProperties`) to retrieve property data.

Command output:

```text
ref created kind=process
event-object-type 2
event-object-id 1730
query EspQueryProcessProperties 0x00000000 buffer=0000008000537EC0
ok   EspRegisterClient                        0x00000000 S_OK
ok   EspConnectClient                         0x00000000 S_OK
ok   EspCreateProcessReference                0x00000000 S_OK
ok   EspGetEventObjectFromReference           0x00000000 S_OK
ok   EspGetEventObjectType                    0x00000000 S_OK
ok   EspGetEventObjectId                      0x00000000 S_OK
ok   EspQueryProcessProperties                0x00000000 S_OK
```

## In-Kernel Collections and Property Capability Probing

WESP supports in-kernel collections that maintain dynamic sets of strings, integers, or binary blobs evaluated directly by in-kernel ROBDD decision graphs. `esptool` provides commands to create, update, and inspect collections, as well as probe whether specific property IDs are supported across platforms:

```powershell
esptool.exe collections --type 2 --lifetime 1
esptool.exe query --kind process --properties 6,20,1,2 --supported 6
```

Collection mechanics:

- `collections --type 2 --lifetime 1` creates a string collection (`type 2`) with transient lifetime (`lifetime 1`).
- `EspCreateCollection` returns a collection GUID.
- `EspUpdateCollection` transmits new entries across `\EspFilterPort`, expanding `$nt:` prefixes to full NT device namespace paths.
- `EspEnumerateCollectionEntries` verifies that entries are active in non-paged pool memory.

Query probing mechanics:

- `--supported 6` calls `EspIsProcessPropertySupported(6)`, probing whether `ProcessId` (`6`) is recognized by the kernel driver on the active Windows build. The export returns `1` for supported.
- `EspQueryProcessProperties` reads the property buffer for the requested property identifiers.

Command output:

```text
collection-id {391d246d-f7bc-dd43-894a-0ab429fa8dad}
collection-type 2
collection-entries 1
ok   EspRegisterClient                        0x00000000 S_OK
ok   EspConnectClient                         0x00000000 S_OK
ok   EspCreateCollection                      0x00000000 S_OK
ok   EspUpdateCollection                      0x00000000 S_OK
ok   EspGetCollectionId                       0x00000000 S_OK
ok   EspGetCollectionType                     0x00000000 S_OK
ok   EspEnumerateCollectionEntries            0x00000000 S_OK

query EspQueryProcessProperties 0x00000000 buffer=000000DF3DE666E0
property-supported process 6 1
ok   EspRegisterClient                        0x00000000 S_OK
ok   EspConnectClient                         0x00000000 S_OK
ok   EspCreateProcessReference                0x00000000 S_OK
ok   EspGetEventObjectFromReference           0x00000000 S_OK
ok   EspQueryProcessProperties                0x00000000 S_OK
ok   EspIsProcessPropertySupported            0x00000000 S_OK
```

## In-Kernel Rule Persistence and Client Lifecycle Management

Standard WESP monitoring sessions use transient rules (`lifetime="transient"`, FFI 1) that the kernel driver automatically removes when the user-mode client disconnects. To enforce policies across client restarts or validate tamper resistance, WESP supports persistent rules (`lifetime="persistent"`, FFI 3) stored in kernel memory and the system registry:

```powershell
esptool.exe persist-rules --rules rules\persist_process_create_empty_deny.xml
esptool.exe clients
esptool.exe enum-rules
esptool.exe unregister --all
```

Operational lifecycle:

1. **Persistent Rule Deployment (`persist-rules`)**: Parses the rule specification, overrides rule lifetime to persistent (`3`), and installs rules without establishing a user-mode queue. The driver persist store stores the rules and maintains client state across process termination.
2. **Client Discovery (`clients`)**: Invokes `EspEnumerateRegisteredClients` to query all active WESP registrations across the system, displaying the persistent client GUID.
3. **Rule Enumeration (`enum-rules`)**: Calls `EspEnumerateRuleIds` to inspect active rule counts broken down by FFI lifetime (lifetimes 1 through 4).
4. **Teardown (`unregister --all`)**: Invokes `EspUnregisterClient` on every discovered client GUID, releasing kernel non-paged quota, clearing BDD decision graphs, and removing persistent registry entries.

Command output:

```text
persist-rules 1
ok   EspRegisterClient                        0x00000000 S_OK
ok   EspConnectClient                         0x00000000 S_OK
ok   EspCreateRule:persist-create             0x00000000 S_OK
ok   EspUpdateRules                           0x00000000 S_OK
ok   EspEnumerateRuleIds                      0x00000000 S_OK

registered-clients 1
client {e43fe653-c426-064d-8811-8b722a964d65}
ok   EspEnumerateRegisteredClients            0x00000000 S_OK

unregistered 1
ok   EspEnumerateRegisteredClients            0x00000000 S_OK
ok   EspUnregisterClient                      0x00000000 S_OK
```

# Where to Learn More

For complete technical specifications, consult the dedicated documentation files:

- **Command and CLI Reference**: For full syntax, options, and diagnostic trace details for all 36 commands, see [docs/esptool_tech_reference.md](docs/esptool_tech_reference.md).
- **Kernel Architecture and Internals**: For in-depth analysis of `wesp.sys`, callback interception, Filter Manager port wire protocols, BDD graph layouts, and disposition tables, see [docs/wesp_re_tech_reference.md](docs/wesp_re_tech_reference.md).
- **Rule Authoring and Property Space**: For XML schema attributes, combinators, relational operators, and property ID catalogs across all 15 executive families, see [rules/README.md](rules/README.md).
