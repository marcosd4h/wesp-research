# Gap live cases dotted into Run-EsptoolSmoke.ps1. Uses the parent
# helpers (Add-Case, New-UniqueRules, New-PendingTrigger,
# Invoke-SerializeRules, Invoke-MonitorTrigger, Invoke-SystemEsp).
$ErrorActionPreference = 'Continue'

if (-not (Get-Command New-PendingTrigger -ErrorAction SilentlyContinue)) {
    throw 'New-PendingTrigger is defined in Run-EsptoolSmoke.ps1 and must be loaded first.'
}
if (-not (Get-Command Invoke-SerializeRules -ErrorAction SilentlyContinue)) {
    throw 'Invoke-SerializeRules is defined in Run-EsptoolSmoke.ps1 and must be loaded first.'
}

Write-Output '===== gap live ====='

$code = Invoke-SystemEsp 'trust_abcd' "--worker trust --permission abcd --dll $Dll" 30
Add-Case 'sys_trust_abcd' '1' $code 'gap' 'restricted discriminator 0xABCD'

Invoke-SerializeRules 'rules_rewrite_serialize' 'enforce_fo_create_empty_rewrite.xml'

$namedLeaf = 'esptool-sm-fo-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$namedFile = Join-Path $OutDir $namedLeaf
$regEv = New-RegProbe
$regDv = New-RegProbe
$regOpen = New-RegProbe
$regSet = New-RegProbe
if (-not $script:Trig) { $script:Trig = New-TriggerImage }
if (-not $script:TrigCmd) { $script:TrigCmd = $script:Trig.CmdLine }

$foOpenLeaf = 'esptool-sm-foopen-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt'
$foOpenPath = Join-Path $OutDir $foOpenLeaf
Invoke-MonitorTrigger -Title 'fo_open_name' -RulesPath (Join-Path $RulesDir 'monitor_fo_open.xml') -TriggerLines @(
    ('echo smoke> "' + $foOpenPath + '"')
    ('type "' + $foOpenPath + '"')
) -Want '0' -BindFileObject -BindValue ('$nt:' + $foOpenPath) -ExpectEvent '2001' -ExpectProps 'FileObject:1'
Invoke-MonitorTrigger -Title 'fo_create_name' -RulesPath (Join-Path $RulesDir 'monitor_fo_create.xml') -TriggerLines @(
    "echo smoke> `"$namedFile`""
) -Want '0' -BindFileObject -BindValue ('$nt:' + $namedFile) -ExpectEvent '2000' -ExpectProps 'FileObject:1,Process:6,Thread:1'
Invoke-MonitorTrigger -Title 'ktm_commit' -RulesPath (Join-Path $RulesDir 'monitor_ktm_commit.xml') -TriggerLines @(
    (New-PendingTrigger 'ktm')
) -Want '0' -DurationMs 16000 -ExpectEvent '3010'
Invoke-MonitorTrigger -Title 'query_ktm' -RulesPath (Join-Path $RulesDir 'monitor_ktm_commit_query_ktm.xml') -TriggerLines @(
    (New-PendingTrigger 'ktm')
) -Want '0' -DurationMs 16000 -ExpectEvent '3010'
Invoke-MonitorTrigger -Title 'ktm_rollback' -RulesPath (Join-Path $RulesDir 'monitor_ktm_rollback.xml') -TriggerLines @(
    (New-PendingTrigger 'ktmrollback')
) -Want '0' -DurationMs 16000 -ExpectEvent '3011'
Invoke-MonitorTrigger -Title 'reg_rename' -RulesPath (Join-Path $RulesDir 'monitor_reg_rename.xml') -TriggerLines @(
    (New-PendingTrigger 'regrename')
) -Want '0' -ExpectEvent '7005' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_setsec' -RulesPath (Join-Path $RulesDir 'monitor_reg_setsec.xml') -TriggerLines @(
    (New-PendingTrigger 'regsetsec')
) -Want '0' -ExpectEvent '7008' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_load' -RulesPath (Join-Path $RulesDir 'monitor_reg_load.xml') -TriggerLines @(
    (New-PendingTrigger 'regload')
) -Want '0' -ExpectEvent '7012' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_enumvalue' -RulesPath (Join-Path $RulesDir 'monitor_reg_enumvalue.xml') -TriggerLines @(
    ("reg add " + $regEv.Hklm + ' /v Smoke /t REG_SZ /d 1 /f')
    ("reg query " + $regEv.Hklm + ' /v Smoke')
    ("reg delete " + $regEv.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7014' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_deletevalue' -RulesPath (Join-Path $RulesDir 'monitor_reg_deletevalue.xml') -TriggerLines @(
    ("reg add " + $regDv.Hklm + ' /v Smoke /t REG_SZ /d 1 /f')
    ("reg delete " + $regDv.Hklm + ' /v Smoke /f')
    ("reg delete " + $regDv.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7004' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'filter_pipe_create_pipe' -RulesPath (Join-Path $RulesDir 'filter_pipe_create_pipe.xml') -TriggerLines @(
    (New-PendingTrigger 'pipe')
) -Want '0' -ExpectEvent '5000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'query_pipe' -RulesPath (Join-Path $RulesDir 'monitor_pipe_create_query_pipe.xml') -TriggerLines @(
    (New-PendingTrigger 'pipe')
) -Want '0' -ExpectEvent '5000' -ExpectProps 'Process:6,Thread:1'
Invoke-MonitorTrigger -Title 'filter_mailslot_create_mailslot' -RulesPath (Join-Path $RulesDir 'filter_mailslot_create_mailslot.xml') -TriggerLines @(
    (New-PendingTrigger 'mailslot')
) -Want '0' -ExpectEvent '6000'
Invoke-MonitorTrigger -Title 'query_mailslot' -RulesPath (Join-Path $RulesDir 'monitor_mailslot_create_query_mailslot.xml') -TriggerLines @(
    (New-PendingTrigger 'mailslot')
) -Want '0' -ExpectEvent '6000'
Invoke-MonitorTrigger -Title 'proc_not' -RulesPath (Join-Path $RulesDir 'filter_process_create_not_process.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000' -ExpectProps 'Process:6,Process:20'
Invoke-MonitorTrigger -Title 'proc_ntpath_neg' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_ntpath_neg.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1'

if (-not $script:SkipHeavy) {
    Invoke-MonitorTrigger -Title 'vol_mount' -RulesPath (Join-Path $RulesDir 'monitor_vol_mount.xml') -TriggerLines @(
        (New-PendingTrigger 'volmount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4000'
    Invoke-MonitorTrigger -Title 'vol_dismount' -RulesPath (Join-Path $RulesDir 'monitor_vol_dismount.xml') -TriggerLines @(
        (New-PendingTrigger 'voldismount')
    ) -Want '0' -DurationMs 22000 -ExpectEvent '4001'
}

Invoke-MonitorTrigger -Title 'reg_open' -RulesPath (Join-Path $RulesDir 'monitor_reg_open.xml') -TriggerLines @(
    ("reg add " + $regOpen.Hklm + ' /f')
    ("reg query " + $regOpen.Hklm)
    ("reg delete " + $regOpen.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7001' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_setvalue' -RulesPath (Join-Path $RulesDir 'monitor_reg_setvalue.xml') -TriggerLines @(
    ("reg add " + $regSet.Hklm + ' /v Smoke /t REG_SZ /d 1 /f')
    ("reg delete " + $regSet.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7003' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'boot_9000' -RulesPath (Join-Path $RulesDir 'monitor_boot_load_driver.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1'

Write-Output '===== gap live done ====='
