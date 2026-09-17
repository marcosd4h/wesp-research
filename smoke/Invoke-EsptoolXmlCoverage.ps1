# Non-naive pumps for rule leaves not covered by the main/gap suites.
# Uses parent helpers. Every leaf here is a -RulesPath or -XmlLeaf argument.
$ErrorActionPreference = 'Continue'
Write-Output '===== xml coverage ====='

if (-not $script:Trig) { $script:Trig = New-TriggerImage }
if (-not $script:TrigCmd) { $script:TrigCmd = $script:Trig.CmdLine }
if (-not $script:ProcReplace) {
    $script:ProcReplace = @{
        '$nt:C:\Windows\System32\cmd.exe' = $script:Trig.NtFilter
        '*cmd.exe'                       = ('*' + $script:Trig.Leaf)
    }
}

$badXor = New-UniqueRules (Join-Path $RulesDir 'fixture_combinator_invalid_eventtype.xml')
if (-not $badXor) {
    Add-Case 'sys_rules_fixture_combinator_invalid_eventtype' '0' 1 'rules' $script:LastRulesError
} else {
    $code = Invoke-SystemEsp 'fixture_combinator_invalid_eventtype' (
        "--worker rules --no-provision --dll $Dll --rules " + $badXor
    ) 30
    Add-Case 'sys_rules_fixture_combinator_invalid_eventtype' '1' $code 'rules' 'invalid eventType fixture'
}

Invoke-SerializeRules 'rules_cancel_serialize' 'enforce_fo_create_empty_cancel.xml' '0x00000000'

Invoke-MonitorTrigger -Title 'enforce_process_deny' -RulesPath (Join-Path $RulesDir 'enforce_process_create_process_deny.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1' -Replace @{ '$nt:C:\tools\esptool_deny_probe.exe' = $script:Trig.NtFilter }

$denyFoLeaf = 'esptool-sm-deny-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$denyFoPath = Join-Path $OutDir $denyFoLeaf
Invoke-MonitorTrigger -Title 'enforce_fo_deny' -RulesPath (Join-Path $RulesDir 'enforce_fo_create_fileobject_deny.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-CreateNew.ps1`" -Path `"$denyFoPath`""
) -Want '1' -Replace @{ '$nt:C:\tools\esptool-gap\deny_create.txt' = ('$nt:' + $denyFoPath) }

Invoke-MonitorTrigger -Title 'enforce_queue_subrules' -RulesPath (Join-Path $RulesDir 'enforce_process_create_empty_queue_subrules.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000'

$foLeaf = 'esptool-sm-xfo-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$foPath = Join-Path $OutDir $foLeaf
$foNt = '$nt:' + $foPath
$prop17 = Join-Path $OutDir 'esptool_prop17.txt'
$regX = New-RegProbe
$adsPath = $foPath + ':esptool'

Invoke-MonitorTrigger -Title 'filter_fo_create_file' -RulesPath (Join-Path $RulesDir 'filter_fo_create_file.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'filter_fo_create_file_prop17' -RulesPath (Join-Path $RulesDir 'filter_fo_create_file_prop17.xml') -TriggerLines @(
    "echo smoke> `"$prop17`""
) -Want '0' -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'filter_fo_create_filestream' -RulesPath (Join-Path $RulesDir 'filter_fo_create_filestream.xml') -TriggerLines @(
    "echo ads> `"$adsPath`""
) -Want '0' -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'filter_ktm_commit_ktm' -RulesPath (Join-Path $RulesDir 'filter_ktm_commit_ktm.xml') -TriggerLines @(
    (New-PendingTrigger 'ktm')
) -Want '0' -DurationMs 16000 -ExpectEvent '3010'
Invoke-MonitorTrigger -Title 'filter_multi_or_not' -RulesPath (Join-Path $RulesDir 'filter_multi_process_or_registry_key_not_process.xml') -TriggerLines @(
    $script:TrigCmd
    ("reg add HKLM\Software\esptool_filter_probe /f")
    ("reg delete HKLM\Software\esptool_filter_probe /f")
) -Want '0' -Replace (@{ 'value="cmd.exe"' = ('value="' + $script:Trig.Leaf + '"') } + $script:ProcReplace) -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_ob_create_desktop' -RulesPath (Join-Path $RulesDir 'filter_ob_create_desktop.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '8000'
Invoke-MonitorTrigger -Title 'filter_process_create_client_bool' -RulesPath (Join-Path $RulesDir 'filter_process_create_client_bool.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_event' -RulesPath (Join-Path $RulesDir 'filter_process_create_event.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_event_bool' -RulesPath (Join-Path $RulesDir 'filter_process_create_event_bool.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_ntpath_labeled' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_ntpath_labeled.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_token' -RulesPath (Join-Path $RulesDir 'filter_process_create_token.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_reg_create_or' -RulesPath (Join-Path $RulesDir 'filter_reg_create_or_registry_key.xml') -TriggerLines @(
    ("reg add HKLM\Software\esptool_filter_probe /f")
    ("reg delete HKLM\Software\esptool_filter_probe /f")
) -Want '1'
Invoke-MonitorTrigger -Title 'filter_reg_delete_rko' -RulesPath (Join-Path $RulesDir 'filter_reg_delete_registry_key_object.xml') -TriggerLines @(
    ("reg add " + $regX.Hklm + ' /f')
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '1'
Invoke-MonitorTrigger -Title 'filter_thread_create_thread' -RulesPath (Join-Path $RulesDir 'filter_thread_create_thread.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '1'
if (-not $script:SkipHeavy) {
    Invoke-MonitorTrigger -Title 'filter_vol_fsctl_disk' -RulesPath (Join-Path $RulesDir 'filter_vol_fsctl_disk.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4002'
    Invoke-MonitorTrigger -Title 'filter_vol_fsctl_volume' -RulesPath (Join-Path $RulesDir 'filter_vol_fsctl_volume.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4002'
}

Invoke-MonitorTrigger -Title 'create_trio' -RulesPath (Join-Path $RulesDir 'monitor_create_trio.xml') -TriggerLines @(
    $script:TrigCmd
    "echo smoke> `"$foPath`""
    ("reg add " + $regX.Hklm + ' /f')
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -BindFileObject -BindFileValue $foNt -BindRegistry -BindRegValue $regX.NtMachine -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'create_trio_action0' -RulesPath (Join-Path $RulesDir 'monitor_create_trio_action0.xml') -TriggerLines @(
    $script:TrigCmd
    "echo smoke> `"$foPath`""
    ("reg add " + $regX.Hklm + ' /f')
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -BindFileObject -BindFileValue $foNt -BindRegistry -BindRegValue $regX.NtMachine -ExpectEvent '1000'

Invoke-MonitorTrigger -Title 'file_create_notify' -RulesPath (Join-Path $RulesDir 'monitor_file_create_notify.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'leftover_families' -RulesPath (Join-Path $RulesDir 'monitor_leftover_families.xml') -TriggerLines @(
    (New-PendingTrigger 'pipe')
    "echo smoke> `"$foPath`""
    "type `"$foPath`""
) -Want '0' -ExpectEventAny '2001,5000'
Invoke-MonitorTrigger -Title 'fo_cleanup' -RulesPath (Join-Path $RulesDir 'monitor_fo_cleanup.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
    "type `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2004'
Invoke-MonitorTrigger -Title 'fo_query_file' -RulesPath (Join-Path $RulesDir 'monitor_fo_create_query_file.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'fo_query_filestream' -RulesPath (Join-Path $RulesDir 'monitor_fo_create_query_filestream.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'fo_query_stream' -RulesPath (Join-Path $RulesDir 'monitor_fo_create_query_stream.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2000'
Invoke-MonitorTrigger -Title 'fo_read' -RulesPath (Join-Path $RulesDir 'monitor_fo_read.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
    "type `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2002'
Invoke-MonitorTrigger -Title 'fo_write' -RulesPath (Join-Path $RulesDir 'monitor_fo_write.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -BindFileObject -BindValue $foNt -ExpectEvent '2003'

Invoke-MonitorTrigger -Title 'fs_fsctl' -RulesPath (Join-Path $RulesDir 'monitor_fs_fsctl.xml') -TriggerLines @(
    "fsutil file setzerodata offset=0 length=1 `"$foPath`""
) -Want '0' -ExpectEvent '3005'
Invoke-MonitorTrigger -Title 'fs_ktm' -RulesPath (Join-Path $RulesDir 'monitor_fs_ktm.xml') -TriggerLines @(
    (New-PendingTrigger 'ktm')
) -Want '0' -DurationMs 16000 -ExpectEventAny '3000,3001,3002,3003,3004,3005,3006,3007,3008,3009,3010,3011'
Invoke-MonitorTrigger -Title 'fs_lock' -RulesPath (Join-Path $RulesDir 'monitor_fs_lock.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-FileLock.ps1`""
) -Want '0' -ExpectEvent '3008'
Invoke-MonitorTrigger -Title 'fs_queryinfo' -RulesPath (Join-Path $RulesDir 'monitor_fs_queryinfo.xml') -TriggerLines @(
    "dir `"$foPath`""
) -Want '0' -ExpectEvent '3001'
Invoke-MonitorTrigger -Title 'fs_queryopen' -RulesPath (Join-Path $RulesDir 'monitor_fs_queryopen.xml') -TriggerLines @(
    "type `"$foPath`""
) -Want '0' -ExpectEvent '3007'
Invoke-MonitorTrigger -Title 'fs_section' -RulesPath (Join-Path $RulesDir 'monitor_fs_section.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-Section.ps1`" `"$foPath`""
) -Want '0' -ExpectEvent '3000'
Invoke-MonitorTrigger -Title 'fs_security' -RulesPath (Join-Path $RulesDir 'monitor_fs_security.xml') -TriggerLines @(
    "icacls `"$foPath`""
) -Want '0' -ExpectEvent '3003'
Invoke-MonitorTrigger -Title 'fs_setea' -RulesPath (Join-Path $RulesDir 'monitor_fs_setea.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '1'
Invoke-MonitorTrigger -Title 'fs_setinfo' -RulesPath (Join-Path $RulesDir 'monitor_fs_setinfo.xml') -TriggerLines @(
    "echo smoke> `"$foPath`""
) -Want '0' -ExpectEvent '3002'
Invoke-MonitorTrigger -Title 'fs_unlock' -RulesPath (Join-Path $RulesDir 'monitor_fs_unlock.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-FileLock.ps1`""
) -Want '0' -ExpectEvent '3009'

Invoke-MonitorTrigger -Title 'ob_query_desktop' -RulesPath (Join-Path $RulesDir 'monitor_ob_create_query_desktop.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '8000'
Invoke-MonitorTrigger -Title 'pipe_mailslot' -RulesPath (Join-Path $RulesDir 'monitor_pipe_mailslot.xml') -TriggerLines @(
    (New-PendingTrigger 'pipemail')
) -Want '0' -DurationMs 16000 -ExpectEventAny '5000,6000'
Invoke-MonitorTrigger -Title 'process_fo_reg_mixed' -RulesPath (Join-Path $RulesDir 'monitor_process_fo_reg_mixed.xml') -TriggerLines @(
    $script:TrigCmd
    "echo smoke> `"$foPath`""
    ("reg add " + $regX.Hklm + ' /f')
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '0' -ExpectEventAny '1001,1002,2001,2003,2004,7001,7003,7010'
Invoke-MonitorTrigger -Title 'process_loadimage' -RulesPath (Join-Path $RulesDir 'monitor_process_loadimage.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1002'
Invoke-MonitorTrigger -Title 'process_terminate' -RulesPath (Join-Path $RulesDir 'monitor_process_terminate.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1001'
Invoke-MonitorTrigger -Title 'reg_delete_query_rko' -RulesPath (Join-Path $RulesDir 'monitor_reg_delete_query_registry_key_object.xml') -TriggerLines @(
    ("reg add " + $regX.Hklm + ' /f')
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7002'
Invoke-MonitorTrigger -Title 'reg_remainder' -RulesPath (Join-Path $RulesDir 'monitor_reg_remainder.xml') -TriggerLines @(
    ("reg add " + $regX.Hklm + ' /f')
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEventAny '7002,7004,7005,7006,7007,7008,7009,7010,7011,7012,7013,7014'
Invoke-MonitorTrigger -Title 'reg_replace' -RulesPath (Join-Path $RulesDir 'monitor_reg_replace.xml') -TriggerLines @(
    (New-PendingTrigger 'regreplace')
) -Want '1'
Invoke-MonitorTrigger -Title 'reg_restore' -RulesPath (Join-Path $RulesDir 'monitor_reg_restore.xml') -TriggerLines @(
    (New-PendingTrigger 'regrestore')
) -Want '1'
Invoke-MonitorTrigger -Title 'reg_save' -RulesPath (Join-Path $RulesDir 'monitor_reg_save.xml') -TriggerLines @(
    ("reg add " + $regX.Hklm + ' /f')
    ("reg save " + $regX.Hklm + " `"$OutDir\esptool-sm-save.hiv`" /y")
    ("reg delete " + $regX.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7011'
Invoke-MonitorTrigger -Title 'thread_handle' -RulesPath (Join-Path $RulesDir 'monitor_thread_handle.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '2'
Invoke-MonitorTrigger -Title 'thread_query' -RulesPath (Join-Path $RulesDir 'monitor_thread_start_query_thread.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '2'
if (-not $script:SkipHeavy) {
    Invoke-MonitorTrigger -Title 'vol_fsctl_query_disk' -RulesPath (Join-Path $RulesDir 'monitor_vol_fsctl_query_disk.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4002'
    Invoke-MonitorTrigger -Title 'vol_fsctl_query_volume' -RulesPath (Join-Path $RulesDir 'monitor_vol_fsctl_query_volume.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4002'
    Invoke-MonitorTrigger -Title 'volume_set' -RulesPath (Join-Path $RulesDir 'monitor_volume_set.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4000'
}
Invoke-MonitorTrigger -Title 'recipe_mprtp' -RulesPath (Join-Path $RulesDir 'recipe_mprtp_pipe_create_empty_fo_open_fileobject_pipe.xml') -TriggerLines @(
    (New-PendingTrigger 'pipe')
) -Want '0' -ExpectEvent '5000'

if (-not (Get-Command Test-NamedDenyRefuseMarker -ErrorAction SilentlyContinue)) {
    function Test-NamedDenyRefuseMarker {
        param([string]$Text)
        if (-not $Text) { return $false }
        return [bool](
            ($Text -match 'needs the espclient.dll enforce-compat patch') -or
            ($Text -match 'the enforce-compat patch is unavailable') -or
            ($Text -match 'enforcing action is unavailable') -or
            ($Text -match 'has no event modify kind')
        )
    }
}

# Enforcing deny coverage. deny_file_create.xml is a document whose action
# actually refuses the operation natively (2000 needs no patch). The enforce
# documents below name event types the unpatched client refuses, so without
# --enforce-compat esptool refuses them at install with a named diagnostic and
# the target operation proceeds (fail closed). deny_registry_create.xml is a
# suppress-labelled UNSUPPORTED fixture: selector 4 installs and does not deny,
# so it is asserted to install, not to refuse.
$realDenyLeaf = 'esptool-sm-realdDeny-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$realDenyPath = Join-Path $OutDir $realDenyLeaf
Invoke-MonitorTrigger -Title 'deny_file_create_blocks' -RulesPath (Join-Path $RulesDir 'deny_file_create.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-CreateNew.ps1`" -Path `"$realDenyPath`""
) -Want '1' -DurationMs 30000 -TriggerDelaySec 10 -Replace @{ '$nt:C:\tools\esptool-deny\file_target.txt' = ('$nt:' + $realDenyPath) }
Add-Case 'deny_file_create_file_absent' '0' ([int](Test-Path -LiteralPath $realDenyPath)) 'deny' 'enforcing deny leaves the target absent'

foreach ($denyLeaf in @('deny_process_create.xml', 'deny_fo_open_fileobject_deny.xml', 'deny_registry_object.xml')) {
    $stem = [System.IO.Path]::GetFileNameWithoutExtension($denyLeaf)
    $title = 'deny_' + $stem
    $unique = New-UniqueRules (Join-Path $RulesDir $denyLeaf)
    if (-not $unique) {
        Add-Case ($title + '_refused') '0' 1 'deny' $script:LastRulesError
        continue
    }
    $code = Invoke-SystemEsp $title ("--worker rules --no-provision --dll $Dll --rules " + $unique) 30
    $sysOut = Join-Path $OutDir ('sys_{0}.out' -f $title)
    $sysText = ''
    if (Test-Path -LiteralPath $sysOut) {
        $sysText = Get-Content -LiteralPath $sysOut -Raw -ErrorAction SilentlyContinue
    }
    $named = Test-NamedDenyRefuseMarker $sysText
    $got = $(if (($code -eq 1) -and $named) { 0 } else { 1 })
    $note = 'named-refuse-miss'
    if ($sysText -match 'the rule document is empty') {
        $note = 'rule-document-empty'
    } elseif ($named) {
        $note = 'enforcing action unavailable without --enforce-compat: fail closed'
    } elseif ($sysText -match '(?m)^(warning:|fail |rule parse error:).+$') {
        $note = $Matches[0].Trim()
    }
    Add-Case ($title + '_refused') '0' $got 'deny' $note
}

$registryFixture = New-UniqueRules (Join-Path $RulesDir 'deny_registry_create.xml')
if (-not $registryFixture) {
    Add-Case 'deny_registry_create_suppress_installs' '0' 1 'deny' $script:LastRulesError
} else {
    $code = Invoke-SystemEsp 'deny_registry_create_suppress' ("--worker rules --no-provision --dll $Dll --rules " + $registryFixture) 30
    Add-Case 'deny_registry_create_suppress_installs' '0' $code 'deny' 'suppress-labelled fixture installs and does not deny'
}

$procDenied = New-TriggerImage
$procControl = New-TriggerImage
Invoke-HeldCompatDeny -Title 'deny_process_create_compat' `
    -RulesPath (Join-Path $RulesDir 'deny_process_create.xml') `
    -Replace @{ '$nt:C:\tools\esptool-deny\proc_target.exe' = $procDenied.NtFilter } `
    -TriggerScript 'Trigger-Spawn.ps1' `
    -DeniedPath $procDenied.Path `
    -ControlPath $procControl.Path `
    -ExpectedDeniedHresult '80004005'

$openDeniedLeaf = 'esptool-sm-open-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$openDeniedPath = Join-Path $OutDir $openDeniedLeaf
$openControlLeaf = 'esptool-sm-open-ctrl-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$openControlPath = Join-Path $OutDir $openControlLeaf
Set-Content -LiteralPath $openDeniedPath -Value 'open-target' -Encoding ASCII
Set-Content -LiteralPath $openControlPath -Value 'open-control' -Encoding ASCII
Invoke-HeldCompatDeny -Title 'deny_fo_open_compat' `
    -RulesPath (Join-Path $RulesDir 'deny_fo_open_fileobject_deny.xml') `
    -Replace @{ '$nt:C:\tools\esptool-deny\fo_open_target.txt' = ('$nt:' + $openDeniedPath) } `
    -TriggerScript 'Trigger-OpenExisting.ps1' `
    -DeniedPath $openDeniedPath `
    -ControlPath $openControlPath `
    -ExpectedDeniedHresult '80070490'

Write-Output '===== xml coverage done ====='
