esptool guest smoke suite

Portable live checks for every `esptool` command and option, plus the
gap recipes used to prove or refute WESP event delivery. The suite runs
on a Windows guest that already has `wesp.sys` loaded and
`espclient.dll` in the default search path.

# Layout

- `Run-EsptoolSmoke.ps1` is the guest entry point. It defines
  `New-PendingTrigger` and `Invoke-SerializeRules` before any dotted
  script so `-DenyOnly` (which skips gap cases) still has those helpers.
- `Start-EsptoolSmokeDetached.ps1` starts the suite from this folder via
  WMI `Win32_Process` Create. `Read-EsptoolSmokeStatus.ps1` reads
  `summary.tsv` in the same folder.
- `Invoke-EsptoolGapCases.ps1` is dotted in after the baseline monitors
  on a full run.
- `Trigger-Pending.ps1` produces KTM, volume, registry rename/load,
  named-pipe, and mailslot events. Mode `pipemail` compiles both IPC
  creates in one process.
- `Trigger-ThreadHandle.ps1` produces thread-start and handle-duplicate
  events.
- `Trigger-CreateNew.ps1` opens a path with `CreateFileW` `CREATE_NEW`
  for FoCreate equals filters.
- Rule XML is `tools/esptool/rules` (118 documents). Leaf names follow
  `tools/esptool/rules/README.md`. On the guest the pusher places those
  leaves in `rules\` next to these scripts.
- `esptool.exe` is the Release binary placed next to these scripts by
  the host pusher (or passed with `-Exe`).
- `results\` is created on the first run. Each case writes an `.out`
  file plus `EXIT=`. `summary.tsv`, `summary.json`, and `coverage.json`
  list verdicts and the command/option map.

# Guest prerequisites

- Elevated administrator PowerShell. Scheduled tasks launch
  `NT AUTHORITY\SYSTEM`.
- `esptool.exe` (Release `/WX` build).
- `C:\Windows\System32\espclient.dll` unless `-Dll` overrides it.
- `wesp` minifilter present (`fltmc filters`).
- Test signing or an Antimalware Protected Light process. A present
  `WESP://Permission` claim without AM-PPL is rejected by
  `EspRegisterClient` with `0x80070057`. The default connect path
  therefore uses `--no-provision`.

# How to copy

The guest folder is self-contained after a push: every `smoke/*.ps1`,
`README.md`, `rules.manifest.json`, the XML leaves from
`tools/esptool/rules`, and the Release `esptool.exe`.
It does not include `work/` probe scripts or other workspace paths.

The host helper `work/push_esptool_smoke.ps1` enumerates those leaves
as per-file WinRM pairs (no directory `Copy-Item`). XML is read from
`tools/esptool/rules`, not from a second tree under `smoke/`. Default
dest is `C:\tools\esptool-smoke-live`.

# How to run

```powershell
cd C:\tools\esptool-smoke-live
powershell -NoProfile -ExecutionPolicy Bypass -File .\Start-EsptoolSmokeDetached.ps1
powershell -NoProfile -ExecutionPolicy Bypass -File .\Read-EsptoolSmokeStatus.ps1
```

Foreground equivalent:

```powershell
powershell -NoProfile -ExecutionPolicy Bypass -File .\Run-EsptoolSmoke.ps1 -Exe .\esptool.exe -RulesDir .\rules -OutDir .\results
```

Optional switches:

- `-Exe <path>`, `-Dll <path>`, and `-RulesDir <path>` override defaults.
- `-OutDir <path>` changes the result directory.
- `-SkipIsolated` skips `exercise --isolated` (one child per export).
- `-SkipHeavy` skips diskpart VHD volume mount and dismount.

The process exit code is `1` when any case is `FAIL`, otherwise `0`.

# What is covered

Commands: `exports`, `status`, `connect`, `rules`, `monitor`, `clients`,
`unregister`, `enum-rules`, `remove-rules`, `persist-rules`,
`open-queue`, `trust`, `query`, `refs`, `collections`, `context`, `exercise`,
`call-one`, `ppl status`,
`token status`, `token set`, `token clear`, `provision`,
`service install`, `service uninstall`,
`service run`, `service foreground`, `ipc ping`,
`ipc status`, `ipc exports`, `ipc exercise`, `ipc rules`.

Options: `--help`, `-h`, `--dll`, `--dll=value`, `--rules`, `--log`,
`--pipe`, `--service`, `--level` (TRACE, DEBUG, warn, error,
info, unknown), `--target`, `--duration`, `--duration=ms`, `--max`,
`--max=count`, `--isolated`, `--json`, `--permission` (restricted and
full), `--no-provision`, `--worker`, `--verbose`, `-v`, `--iocp`,
`--enforce-compat`,
`--guid`, `--guid=value`, `--kind`, `--pid`, `--tid`, `--path`,
`--file-id`, `--volume`, `--stream`, `--name`, `--event-id`,
`--properties`, `--supported`, `--from-notify`, `--duplicate`,
`--context-enum`, `--type`, `--lifetime`, `--enum-ids`, `--open`, `--`,
and the non-prefix `--helpfulness` reject. Missing values for the new
string and count flags are exit `2`. `collections --type xyz` and
`collections --lifetime xyz` are exit `2`.

Monitor and `rules` cases rewrite a unique client name and altitude
(starting at `710000`) through `New-UniqueRules`. That helper rewrites
only the `<client>` `name=` and `altitude=` attributes. Static
`[regex]::Replace(..., 1)` is a `RegexOptions` value, not a replace
count, and would also rewrite `<collection name=` and `<rule name=`.

`fixture_process_create_process_bad_eventtype.xml` and
`fixture_collection_open_missing_guid.xml` are expected to exit `1`.
`enforce_fo_create_empty_rewrite.xml` is a serialize-proof case: PASS
when CreateRule is `S_OK` and UpdateRules is `0x80070057`.
`connect --no-provision` after `unregister --all` is expected to exit
`0`.

Every want-`0` `Invoke-MonitorTrigger` call must pass `-ExpectEvent`
and/or `-ExpectName`. A want-`0` call with neither binder is FAIL
(`unbound-want0`). `ExpectEvent` matches `event=<id>` followed by
whitespace or end of line, so `event=1000` does not match
`event=10000`. ProcessCreate pumps copy `cmd.exe` to
`esptool-sm-trig-<8hex>.exe` under `-OutDir` and require that leaf
in a `name=` field. Filters that hard-code `$nt:...cmd.exe` or
`*cmd.exe` are rewritten to that unique path.

`monitor` still exits `1` on zero notifications. `coverage.json`
`events` maps only those sparse ids that still have a remaining
want-`0` or want-`1` case. Current ids: thread `2`/`3`, process
`1000`, FoCreate/FoOpen `2000`/`2001`, directory `3004`, KTM
`3010`/`3011`, volume mount/dismount `4000`/`4001` (omitted when
`-SkipHeavy`), pipe `5000`, mailslot `6000`, registry `7000`-`7005` /
`7008`-`7010` / `7012`-`7014`, object-handle `8001`, and boot `9000`
(UpdateRules reject). `event_id_coverage` FAILs if a mapped id has no
case.

Also pumped: FoCreate/FoOpen with a unique probe leaf, FoCreate
file-object equals (`REPLACE_FO_EQUALS`) and its idle negative,
RegCreateKey plus `query kind=registry`, filtered pipe and mailslot,
process NT-path equals and negative, `--iocp`, AND/XOR/implicit-AND
ProcessCreate filters, named/integer/binary collections, and the
process/event/token/client `<query>` documents. Unfiltered FoOpen
(`monitor_fo_open` without a name binder) is not in the suite.
SYSTEM hops without `--worker` cover `connect`, `provision`, `query`,
`refs`, `collections`, `context`, `rules`, idle `monitor`, `clients`,
`trust`, `enum-rules`, and `open-queue`. Admin hop denial is checked
for every `CommandNeedsWorker` command.

`refs` covers process (including `--properties` / `--supported` /
`--duplicate` / `--context-enum`), file ByPath, registry
`HKLM\Software`, thread, desktop `Default`, process-token, thread-token
(`token` plus `--tid` and empty `--pid`), stream ByPath, missing kind
(exit `1`), `--from-notify` without `--rules` (exit `1`), and
`--from-notify` on `monitor_process_create_query_process.xml` and
`monitor_fo_create_query_fileobject.xml`. `query --kind` covers process,
token, stream, event (prints that `EspQueryEventProperties` is absent),
event without `--supported` (exit `1`), ktm, client, client without
`--properties` or `--supported` (exit `1`), and registry-key-object.
`collections` covers no-flag string smoke, `--type 1`, `--type 3`, and
`--type 2 --enum-ids --lifetime 1 --open` in one session.

Monitor pumps include process `<query>` documents (`process`, `event`,
`token`, `client`, `process-token`),
`filter_process_create_and_process.xml`,
`filter_process_create_xor_process.xml`, implicit AND,
`monitor_create_trio_named.xml`, `monitor_process_create_type0.xml`,
and the named / integer / binary collection ProcessCreate documents.

`unregister` covers missing `--guid` (exit `2`), a non-GUID value
(exit `2`), and a well-formed zero GUID (`--guid` and `--guid=value`).
`persist-rules` and `clients` are a lifecycle: `unregister --all`,
then `persist-rules` stdout matching `persist-rules [1-9][0-9]*`,
then `clients` matching `registered-clients [1-9][0-9]*`, then
`unregister --all`, then `clients` matching `registered-clients 0`.
`exports` requires `resolved N of M` with N and M at least 1.
`connect --no-provision` requires `ok EspConnectClient 0x00000000`.
Missing or empty stdout on an `-ExpectText` case is FAIL.
`trust --permission abcd` is expected to exit `1`.

`service install` is checked with `--no-provision`, without it
(ImagePath omits the flag), as a duplicate (exit `1`), and as
`--service=value`. SCM `sc.exe start` is proven by `ipc ping` on the
default `esptool` pipe. `service foreground` listens on the
`--service` name; `--pipe` is ignored by `RunForeground`.

# Gap scoring

A path is treated as working only when `EspCreateRule` and
`EspUpdateRules` return `S_OK` and the monitor prints at least one
typed `event=` line. Armed-and-silent is FAIL (`want` `0`, `monitor`
exit `1`).

- Named FoOpen / FoCreate: want `0`, `event=2001` or `event=2000`,
  and `name=` containing the unique probe leaf.
- KTM, volume mount/dismount, registry rename / set-security / load,
  filtered pipe and mailslot: want `0` plus the matching `ExpectEvent`.
- Rewrite: serialize-proof PASS (`create=S_OK`,
  `update=0x80070057`).
- `filter_process_create_process_ntpath_neg.xml` is a negative
  control (want `1`).
- `monitor_boot_load_driver.xml` is an UpdateRules reject (want `1`).

`Add-Case` accepts only `0`, `1`, `2`, and `nz`. Any other `want`
string is FAIL.

# Enforcing deny coverage

`cli_help_enforce_compat` requires `--help` to name `--enforce-compat`.

Native FoCreate (`2000`) deny is held under `monitor` and scored by
target absence (`deny_file_create_file_absent`).

`deny_process_create.xml`, `deny_fo_open_fileobject_deny.xml`, and
`deny_registry_object.xml` are first installed without `--enforce-compat`.
A refuse row PASSes only when the worker exits `1` and
`sys_deny_*.out` contains a named diagnostic (`needs the espclient.dll
enforce-compat patch`, `the enforce-compat patch is unavailable`,
`enforcing action is unavailable`, or `has no event modify kind`).
`the rule document is empty` is FAIL. XML comments must not contain
`--`; XmlLite then never sees the `<esptool>` root.

`Invoke-HeldCompatDeny` then holds `--worker rules --enforce-compat
--duration` as SYSTEM, polls the redirected holder log for the exact
patch lines (`enforce-compat: rule` plus `installed via in-memory
client patch`, or `the enforce-compat patch is unavailable` /
`needs the espclient.dll enforce-compat patch`), and only then runs a
trigger. A patched holder scores:

- ProcessCreate `1000`: `Trigger-Spawn.ps1` must print
  `operation=DENIED 0x80004005`; a second unique image must print
  `operation=OK`.
- FoOpen `2001`: `Trigger-OpenExisting.ps1` must print
  `operation=DENIED 0x80070490` against an existing target file; a
  second existing file must print `operation=OK`.

A guest whose `espclient.dll` fails the SHA-256 patch gate records
`*_compat_logged` from the refused marker and does not add live-deny
rows. `deny_registry_create.xml` stays `action="suppress"` and is
install-only. There is no passing `7000` deny case.

`Run-EsptoolSmoke.ps1 -DenyOnly` runs host facts, `--help` /
`cli_help_enforce_compat`, and `Invoke-EsptoolXmlCoverage.ps1`, then
writes the summary. It skips CLI parse, SYSTEM hops, gap cases,
exercise, service/IPC, and the full-suite coverage-map rows.

# Deny retest on 10.0.29667 (2026-09-14)

WINVM_102 (`WIN25H2-IDA`) earlier `results-102-deny` was **53 PASS /
1 FAIL / 54 total**. The FAIL was `monitor_pipe_mailslot`
(`received=0` / `event-miss`). `-DenyOnly` skipped
`Invoke-EsptoolGapCases.ps1`, which was then the only definition of
`New-PendingTrigger`, so XmlCoverage trigger lines were empty.

The runner now owns `New-PendingTrigger` and `Invoke-SerializeRules`.
`pipe_mailslot` uses one-process `pipemail`, `DurationMs 16000`, and
`ExpectEventAny '5000,6000'`. That case PASSed on the later full run
(`received=3 events=5000,6000`).

Deny rows from that DenyOnly pass (unchanged contract):

- `cli_help_enforce_compat` PASS
- `deny_file_create_file_absent` PASS
- `deny_deny_process_create_refused`,
  `deny_deny_fo_open_fileobject_deny_refused`,
  `deny_deny_registry_object_refused` PASS with the named fail-closed
  diagnostic
- `deny_registry_create_suppress_installs` PASS (`EspCreateRule` /
  `EspUpdateRules` `S_OK` for `deny-reg-create-unsupported`)
- `deny_process_create_compat_compat_logged` and
  `deny_fo_open_compat_compat_logged` PASS `refused` (`espclient.dll`
  SHA-256 does not match the verified build). No `*_denied` /
  `*_negative` rows.

# WINVM_120 full suite (2026-09-14, incomplete)

The detached full run on HVHOST120 (`results-fresh`) last reported
**98 PASS / 160 FAIL / 258 rows** with `smoke_alive=1`, still inside
`Invoke-EsptoolXmlCoverage.ps1` monitors (`monitor_fo_cleanup`
event-miss). `cli_help_enforce_compat` PASS. Deny rows were not
written before Management WinRM dropped.

Proxmox QEMU VMID 120 stayed `running` on snapshot
`lab_kd_wesp_live_ready_29641`. `192.168.200.120` then returned
destination-host-unreachable (Proxmox `192.168.68.90`) from the task
host and from WINVM_100. Guest-agent NIC query is unavailable
(`No QEMU guest agent configured`). Collect deny rows after Management
WinRM returns; do not treat the 258-row TSV as a finished suite.

# Live results on 10.0.29641

WINVM_120 (HVHOST120) after detached leftover VHD cleanup and
`unregister --all`: **220 PASS / 35 FAIL / 255 total**. Full TSV:
`work/esptool_vm120_signed_smoke/summary.tsv`.

What works: ABI stdout (`exports`, `connect --no-provision`,
`persist-rules` / `clients` lifecycle), FoCreate equals and its
negative, `RegCreateKey` plus registry query, thread / KTM / volume /
pipe / mailslot `ExpectEvent` pumps, `exercise`, IPC, and
`event_id_coverage`.

What this build does not provide:

- ProcessCreate and most registry notifies leave `name=-` (or a
  PsExec wrapper path). `ExpectName` unique-leaf checks FAIL while
  `event=` still arrives.
- `<and>` / implicit AND ProcessCreate still fail UpdateRules
  (`E_INVALIDARG`).
- `fltmc unload wesp` returns `0x801f0010`; client reset is
  `unregister --all`, not a filter unload.

# Live results on 10.0.29667

WINVM_102 (hostname `WIN25H2-IDA`, testsigning Yes, `wesp` at
altitude 329500) ran the self-contained folder
`C:\tools\esptool-smoke-live` (16 suite scripts plus `esptool.exe`
752128 bytes, `rules` `have=116 want=116`, no `work/` leaves) on
2026-09-14: **321 PASS / 0 FAIL / 321 total**. `smoke_alive` returned
to 0. `xml_leaf_coverage` (`leaves=131`) and `event_id_coverage`
(`ids=26`) passed. `monitor_pipe_mailslot` recorded
`events=5000,6000`. `sys_exercise` and `sys_exercise_isolated` exited
0. Artifact: `C:\tools\esptool-smoke-live\results\summary.json`
(62529 bytes).

An earlier bound run on the same guest after every rule XML leaf was
copied (`have=115 want=115`) was **317 PASS / 0 FAIL / 317 total** at
`C:\tools\esptool-smoke\results-102\summary.json`.

Two defects were found and fixed while binding that run:

- **`summary.json` serialized to `null`.** `Run-EsptoolSmoke.ps1` built the
  summary with `cases = @($script:Cases)`. On PowerShell 7.6.x the array
  subexpression throws `ArgumentException: Argument types do not match` for a
  `System.Collections.Generic.List[object]`, which terminates the statement and
  leaves the summary unassigned, so `ConvertTo-Json` wrote the literal `null`.
  The summary now materializes the list with `.ToArray()` and fails loudly if
  the serialized document comes back empty or `null`.
- **`--worker monitor` did not hold for a non-queue rule.** `PumpNotifications`
  returned immediately when no event queue existed, so a monitor run over an
  `action="deny"` document disconnected straight away and the transient rule was
  removed before a trigger could reach it. Measured on build 10.0.29667: the
  monitor returned in under a second and the target create succeeded, while the
  same document installed with `--worker rules --duration` denied it. The pump
  now honors the hold duration when there is no queue, and the enforcing deny is
  verified live under the monitor path (`create=1168`, file absent).

`Invoke-MonitorTrigger` launches the monitor and the trigger with
`-NoPsExec` (scheduled tasks). Bind inserts apply only to empty rules
(`<query>` siblings are allowed; `<filter type="0"/>` is not rewritten).

Measured binders on this guest:

- Empty ProcessCreate monitors insert a type-10 `$nt:` unique image
  (`bind-inserted received=1 events=1000`). ProcessCreate `name=` stays
  `-`.
- `RegCreateKey` (`7000`) accepts type-8
  `\REGISTRY\MACHINE\SOFTWARE\<leaf>`. Notify `name=` decodes. QueryKey
  `7009`, EnumKey `7013`, DeleteKey `7002`, and QueryValue `7010` reject
  that type-8 leaf (`EspCreateRule 0x80070057`). Those documents stay
  empty-filter plus `ExpectEvent`.
- Multi-rule empty documents insert one typed leaf per bind kind.
  `monitor_create_trio_named.xml` produced `received=3
events=1000,2000,7000`.
- `<and>` and implicit sibling AND still return `E_INVALIDARG` (want
  `1`). `<xor>` ProcessCreate installs.
- `EspUpdateRules` on `enforce_fo_create_empty_cancel.xml` returns
  `S_OK`. Rewrite serialize still returns `update=0x80070057`.
- `RegReplaceKey`, `RegRestoreKey`, `FsSetEa`, OR-contains registry,
  and type-9 `value=1` delete install and produce zero matching
  notifies (want `1`).

# Expected non-zero exits

These are contract outcomes, not tool defects:

- Admin hop commands (`connect`, `query`, `provision`, `clients`,
  `unregister`, `enum-rules`, `remove-rules`, `persist-rules`,
  `open-queue`, `trust`, ...) exit `1` because `HopToWorker` requires
  SYSTEM plus `SeTcbPrivilege`.
- Admin `token set`, `token clear`, and any non-`status` token
  subcommand exit `1` because the TCB gate runs before subcommand parse.
  `token not-a-sub` and `token set not-a-perm` exit `2` only as SYSTEM.
- Each `esptool.exe` invocation is a new process. `token set` in one
  scheduled task does not leave a claim for `token clear` in the next.
- `connect --permission restricted|full` exits `1` when the claim is
  present and the process is not AM-PPL (`EspRegisterClient 0x80070057`).
- `token clear` in a fresh SYSTEM process exits `1` (`0xC0000225`)
  because the claim is per-process.
- `provision --no-provision` in a fresh process exits `1` when the
  claim is absent.
- Idle `monitor` exits `1` when zero notifications arrive.
- `service run` outside the service control manager exits `1`.
- `CreateService` ImagePath is `esptool.exe service run --log ...` and
  does not append `--service <name>`. After `sc.exe start`, the pipe
  name is the default `esptool`, not the SCM service name, so
  `ipc ping --pipe esptool` succeeds (exit `0`).
- Repeated runs leave `EspRegisterClient` identities at altitude
  `385000` plus 10. After the 8-step retry window is full, `connect
--no-provision` and every `rules` install that must connect exit `1`.
  Unload `wesp` or reboot the guest before treating that as a tool
  defect.

# SYSTEM launch

SYSTEM cases use a scheduled task whose wrapper is:

```
esptool.exe <args> > out 2>&1
echo EXIT=%ERRORLEVEL% >> out
```

The space before `>>` is required. A wrapper that writes
`echo EXIT=%ERRORLEVEL%>>out` can concatenate the exit marker onto the
previous line and break `Wait-Out`.
