#Requires -RunAsAdministrator
<#
.SYNOPSIS
  Guest-side live smoke for every esptool command and option.

.DESCRIPTION
  Copy this folder and esptool.exe onto the guest. Rule XML lives in
  tools/esptool/rules on the host; the pusher places those leaves in
  rules\ next to this script on the guest.
  Run elevated. SYSTEM hops use scheduled tasks. Each case writes
  stdout plus EXIT= under -OutDir and a TSV/JSON summary.

  Expected codes come from the tool contract: hop commands require
  SYSTEM+TCB; a present
  WESP://Permission claim is rejected by wesp.sys Register
  (0x80070057) unless the process is AM-PPL; token claims are
  per-process; monitor exits 1 when zero notifications arrive.

.PARAMETER Exe
  Path to esptool.exe. Default: esptool.exe next to this script,
  then C:\tools\esptool.exe.

.PARAMETER Dll
  Path to espclient.dll. Default: C:\Windows\System32\espclient.dll.

.PARAMETER RulesDir
  Rule XML directory. Default: rules\ next to this script (guest
  payload), then ..\rules (in-repo tools/esptool/rules), then
  C:\tools\esptool-rules.

.PARAMETER OutDir
  Result directory. Default: results\ next to this script.

.PARAMETER SkipIsolated
  Skip exercise --isolated (one child per export).

.PARAMETER SkipHeavy
  Skip diskpart VHD volume mount and dismount pumps.

.PARAMETER DenyOnly
  Run host facts, --help / enforce-compat, and the XML deny coverage
  block only. Used to retest deny scoring without the full suite.
#>
param(
    [string]$Exe,
    [string]$Dll = 'C:\Windows\System32\espclient.dll',
    [string]$RulesDir,
    [string]$OutDir,
    [switch]$SkipIsolated,
    [switch]$SkipHeavy,
    [switch]$DenyOnly
)

$ErrorActionPreference = 'Continue'
$script:Root = $PSScriptRoot
if (-not $script:Root) { $script:Root = (Get-Location).Path }

function Resolve-Existing([string[]]$Candidates) {
    foreach ($path in $Candidates) {
        if ($path -and (Test-Path -LiteralPath $path)) { return $path }
    }
    return $null
}

function Resolve-RulesDir([string[]]$Candidates) {
    foreach ($path in $Candidates) {
        if (-not $path -or -not (Test-Path -LiteralPath $path)) { continue }
        $xml = @(Get-ChildItem -LiteralPath $path -Filter '*.xml' -ErrorAction SilentlyContinue)
        if ($xml.Count -gt 0) { return $path }
    }
    return $null
}

if (-not $Exe) {
    $Exe = Resolve-Existing @(
        (Join-Path $script:Root 'esptool.exe')
        'C:\tools\esptool.exe'
    )
}
if (-not $RulesDir) {
    $RulesDir = Resolve-RulesDir @(
        (Join-Path $script:Root 'rules')
        (Join-Path $script:Root '..\rules')
        'C:\tools\esptool-rules'
    )
}
if (-not $OutDir) {
    $OutDir = Join-Path $script:Root 'results'
}

if (-not $Exe -or -not (Test-Path -LiteralPath $Exe)) {
    Write-Error 'esptool.exe not found. Pass -Exe or place esptool.exe next to this script.'
    exit 2
}
if (-not $RulesDir -or -not (Test-Path -LiteralPath $RulesDir)) {
    Write-Error 'rules directory not found. Pass -RulesDir or use tools/esptool/rules.'
    exit 2
}
if (-not (Test-Path -LiteralPath $Dll)) {
    Write-Error ("espclient.dll not found: {0}" -f $Dll)
    exit 2
}

$Exe = (Resolve-Path -LiteralPath $Exe).Path
$RulesDir = (Resolve-Path -LiteralPath $RulesDir).Path
$Dll = (Resolve-Path -LiteralPath $Dll).Path
$OutDir = [System.IO.Path]::GetFullPath($OutDir)

New-Item -ItemType Directory -Force -Path $OutDir | Out-Null
$script:RewriteDir = Join-Path $OutDir 'rewritten-rules'
New-Item -ItemType Directory -Force -Path $script:RewriteDir | Out-Null
$script:SummaryTsv = Join-Path $OutDir 'summary.tsv'
$script:SummaryJson = Join-Path $OutDir 'summary.json'
$script:CoverageJson = Join-Path $OutDir 'coverage.json'
$script:Cases = New-Object System.Collections.Generic.List[object]
$script:RulesUsed = New-Object 'System.Collections.Generic.HashSet[string]'
Set-Content -LiteralPath $script:SummaryTsv -Value "case`twant`tgot`tverdict`tgroup`tnote" -Encoding UTF8
$script:TaskPrefix = 'Esptool-Smoke-'
$script:Wd = Split-Path -Parent $Exe
if (-not $script:Wd) { $script:Wd = 'C:\tools' }
$script:SkipHeavy = [bool]$SkipHeavy
$script:LastRulesError = ''

function Add-Case {
    param(
        [string]$Name,
        [string]$Want,
        $Got,
        [string]$Group,
        [string]$Note = ''
    )
    if ($Got -is [System.Array]) { $Got = $Got | Select-Object -Last 1 }
    if ($null -eq $Got) { $Got = -1 }
    $Got = [int]$Got
    $verdict = 'FAIL'
    if ($Want -eq '0' -and $Got -eq 0) { $verdict = 'PASS' }
    elseif ($Want -eq '1' -and $Got -eq 1) { $verdict = 'PASS' }
    elseif ($Want -eq '2' -and $Got -eq 2) { $verdict = 'PASS' }
    elseif ($Want -eq 'nz' -and $Got -ne 0) { $verdict = 'PASS' }
    $row = [pscustomobject]@{
        name    = $Name
        want    = $Want
        got     = $Got
        verdict = $verdict
        group   = $Group
        note    = $Note
    }
    $script:Cases.Add($row)
    $line = "{0}`t{1}`t{2}`t{3}`t{4}`t{5}" -f $Name, $Want, $Got, $verdict, $Group, ($Note -replace "`t", ' ')
    Add-Content -LiteralPath $script:SummaryTsv -Value $line -Encoding UTF8
    Write-Output ("RESULT {0} want={1} got={2} {3} [{4}] {5}" -f $Name, $Want, $Got, $verdict, $Group, $Note)
}

function Start-SystemCmd {
    param([string]$TaskName, [string]$CmdFile, [switch]$NoPsExec)
    $psexec = $null
    if ($env:ESPTOOL_USE_PSEXEC -and -not $NoPsExec) {
        foreach ($cand in @('C:\tools\PsExec64.exe', (Join-Path $script:Wd 'PsExec64.exe'))) {
            if (Test-Path -LiteralPath $cand) { $psexec = $cand; break }
        }
    }
    if ($psexec) {
        # -d keeps monitor+trigger overlapping. The wrapper writes EXIT=.
        cmd.exe /c "`"$psexec`" -accepteula -nobanner -d -s -w `"$script:Wd`" cmd.exe /c `"$CmdFile`"" | Out-Null
        return
    }
    Unregister-ScheduledTask -TaskName $TaskName -Confirm:$false -ErrorAction SilentlyContinue
    $action = New-ScheduledTaskAction -Execute 'cmd.exe' -Argument ("/c `"$CmdFile`"") -WorkingDirectory $script:Wd
    $principal = New-ScheduledTaskPrincipal -UserId 'NT AUTHORITY\SYSTEM' -LogonType ServiceAccount -RunLevel Highest
    $settings = New-ScheduledTaskSettingsSet -AllowStartIfOnBatteries -DontStopIfGoingOnBatteries -MultipleInstances IgnoreNew
    Register-ScheduledTask -TaskName $TaskName -Action $action -Principal $principal -Settings $settings -Force | Out-Null
    Start-ScheduledTask -TaskName $TaskName | Out-Null
}

function Wait-Out {
    param([string]$Path, [int]$Seconds)
    $deadline = (Get-Date).AddSeconds($Seconds)
    do {
        Start-Sleep -Milliseconds 250
        if (Test-Path -LiteralPath $Path) {
            $text = Get-Content -LiteralPath $Path -Raw -ErrorAction SilentlyContinue
            if ($text -and $text -match 'EXIT=') { return $true }
        }
    } while ((Get-Date) -lt $deadline)
    return $false
}

function Stop-SmokeTasks {
    Get-ScheduledTask -ErrorAction SilentlyContinue |
        Where-Object { $_.TaskName -like ($script:TaskPrefix + '*') } |
        ForEach-Object {
            Unregister-ScheduledTask -TaskName $_.TaskName -Confirm:$false -ErrorAction SilentlyContinue
        }
}

$script:AltitudeSeq = 710000
function New-UniqueRules {
    param(
        [string]$Src,
        [hashtable]$Replace = @{}
    )
    $script:LastRulesError = ''
    if (-not $Src -or -not (Test-Path -LiteralPath $Src)) {
        $script:LastRulesError = 'rules-src-missing'
        return $null
    }
    if ((Get-Item -LiteralPath $Src).Length -le 0) {
        $script:LastRulesError = 'rules-src-empty'
        return $null
    }
    $leaf = [System.IO.Path]::GetFileNameWithoutExtension($Src)
    $dst = Join-Path $script:RewriteDir ($leaf + '-' + $script:AltitudeSeq + '.xml')
    $name = 'esptool-sm-' + [guid]::NewGuid().ToString('N').Substring(0, 12)
    $alt = [string]$script:AltitudeSeq
    $script:AltitudeSeq += 10
    $text = [System.IO.File]::ReadAllText($Src)
    # Static [regex]::Replace(..., 1) is RegexOptions, not a replace count.
    # Documents with <collections> have multiple name= attributes; only the
    # client identity must change.
    $clientName = [regex]'<client(?<pre>[^>]*)\bname="[^"]+"'
    $text = $clientName.Replace($text, {
            param($match)
            return ('<client{0}name="{1}"' -f $match.Groups['pre'].Value, $name)
        }, 1)
    $altitudeRx = [regex]'altitude="[^"]+"'
    $text = $altitudeRx.Replace($text, ('altitude="{0}"' -f $alt), 1)
    if ($Replace) {
        foreach ($key in $Replace.Keys) {
            $text = $text.Replace([string]$key, [string]$Replace[$key])
        }
    }
    [System.IO.File]::WriteAllText($dst, $text, [System.Text.UTF8Encoding]::new($false))
    $written = ''
    if (Test-Path -LiteralPath $dst) {
        $written = [System.IO.File]::ReadAllText($dst)
    }
    if ((-not $written) -or ($written -notmatch '<esptool\b') -or
        ((Get-Item -LiteralPath $dst).Length -le 0)) {
        $script:LastRulesError = 'rules-rewrite-empty'
        Remove-Item -LiteralPath $dst -Force -ErrorAction SilentlyContinue
        return $null
    }
    if ($null -ne $script:RulesUsed) {
        [void]$script:RulesUsed.Add([System.IO.Path]::GetFileName($Src))
    }
    return $dst
}

function Test-RuleHasFilterChild {
    param([string]$Inner)
    return [bool]($Inner -match '<filter\b' -or $Inner -match '<and\b' -or $Inner -match '<or\b' -or $Inner -match '<xor\b' -or $Inner -match '<not\b')
}

function Test-RuleMatchesBindKind {
    param([string]$Attrs, [string]$Kind)
    $eventType = -1
    $eventName = ''
    if ($Attrs -match 'eventType="(\d+)"') { $eventType = [int]$Matches[1] }
    if ($Attrs -match 'event="([^"]+)"') { $eventName = $Matches[1] }
    switch ($Kind) {
        'process' {
            return ($eventType -eq 1000) -or ($eventName -eq 'ProcessCreate')
        }
        'fileobject' {
            return (($eventType -ge 2000) -and ($eventType -le 2004)) -or
                ($eventName -match '^(Fo|fo_|FileCreate)')
        }
        'registry' {
            return ($eventType -eq 7000) -or ($eventName -ieq 'RegCreateKey')
        }
        default { return $false }
    }
}

function Add-UniqueEqualsFilter {
    param(
        [string]$XmlText,
        [ValidateSet('process', 'fileobject', 'registry')]
        [string]$Kind,
        [string]$Value
    )
    $leaf = switch ($Kind) {
        'process' { '<filter type="10" comparand="1" property="1" value="{0}"/>' -f $Value }
        'fileobject' { '<filter type="6" comparand="1" property="1" value="{0}"/>' -f $Value }
        'registry' { '<filter type="8" comparand="1" property="1" value="{0}"/>' -f $Value }
    }
    $rx = [regex]'(?s)<rule\b(?<attrs>[^>]*?)(?:/>|>(?<inner>.*?)</rule>)'
    $inserted = $false
    $builder = New-Object System.Text.StringBuilder
    $last = 0
    foreach ($match in $rx.Matches($XmlText)) {
        [void]$builder.Append($XmlText.Substring($last, $match.Index - $last))
        $attrs = $match.Groups['attrs'].Value
        $inner = $match.Groups['inner'].Value
        $chunk = $match.Value
        if ((Test-RuleMatchesBindKind $attrs $Kind) -and -not (Test-RuleHasFilterChild $inner)) {
            $chunk = ('<rule{0}>{1}{2}</rule>' -f $attrs, $inner, $leaf)
            $inserted = $true
        }
        [void]$builder.Append($chunk)
        $last = $match.Index + $match.Length
    }
    [void]$builder.Append($XmlText.Substring($last))
    return [pscustomobject]@{
        Text     = $builder.ToString()
        Inserted = $inserted
    }
}

function New-TriggerImage {
    $leaf = 'esptool-sm-trig-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.exe'
    $path = Join-Path $OutDir $leaf
    Copy-Item -LiteralPath 'C:\Windows\System32\cmd.exe' -Destination $path -Force
    return [pscustomobject]@{
        Path     = $path
        Leaf     = $leaf
        NtFilter = ('$nt:' + $path)
        CmdLine  = ('"' + $path + '" /c echo esptool-smoke-process-trigger')
    }
}

function New-RegProbe {
    $leaf = 'esptool-sm-reg-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
    return [pscustomobject]@{
        Leaf      = $leaf
        Hkcu      = ('HKCU\Software\' + $leaf)
        Hklm      = ('HKLM\Software\' + $leaf)
        NtMachine = ('\REGISTRY\MACHINE\SOFTWARE\' + $leaf)
    }
}

function Invoke-AdminEsp {
    param([string]$Title, [string]$ArgLine)
    Write-Output ""
    Write-Output ("===== admin:" + $Title + " =====")
    $stdout = Join-Path $OutDir ("admin_{0}.out" -f $Title)
    Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue
    $argArray = @()
    if ($ArgLine) { $argArray = $ArgLine -split ' ' }
    & $Exe @argArray > $stdout 2>&1
    $code = [int]$LASTEXITCODE
    "EXIT=$code" | Add-Content -LiteralPath $stdout
    Get-Content -LiteralPath $stdout -ErrorAction SilentlyContinue | Select-Object -First 12
    return $code
}

function Invoke-SystemEsp {
    param(
        [string]$Title,
        [string]$ArgLine,
        [int]$WaitSeconds = 45,
        [string]$ExpectText = ''
    )
    Write-Output ""
    Write-Output ("===== system:" + $Title + " =====")
    if ($null -ne $script:RulesUsed -and $ArgLine -match '--rules(?:\s+|=)(\S+)') {
        [void]$script:RulesUsed.Add([System.IO.Path]::GetFileName($Matches[1]))
    }
    $stdout = Join-Path $OutDir ("sys_{0}.out" -f $Title)
    $wrapper = Join-Path $env:TEMP ("esptool_smoke_{0}.cmd" -f $Title)
    Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue
    @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "`"$Exe`" $ArgLine > `"$stdout`" 2>&1"
        "echo EXIT=%ERRORLEVEL% >> `"$stdout`""
    ) -join "`r`n" | Set-Content -LiteralPath $wrapper -Encoding ASCII
    $task = $script:TaskPrefix + $Title
    Start-SystemCmd $task $wrapper
    [void](Wait-Out $stdout $WaitSeconds)
    $code = -1
    $text = ''
    if (Test-Path -LiteralPath $stdout) {
        $text = Get-Content -LiteralPath $stdout -Raw
        if ($text -match 'EXIT=(-?\d+)') { $code = [int]$Matches[1] }
        Get-Content -LiteralPath $stdout |
            Select-String -Pattern 'EXIT=|EspRegisterClient|EspCreateRule|EspUpdateRules|received |total |faulted |attribute:|error|fail |ppl:|service |ref created|EspCreateProcess|EspCreateFile|EspCreateRegistry|EspCreateEvent|EspCreateThread|EspCreateDesktop|EspCreateCollection|EspOpenCollection|EspEnumerateCollection|EspQuery|EspIs|not exported|collection |registered-clients |persist-rules |resolved |open-queue ' |
            ForEach-Object { Write-Output $_.Line }
    } else {
        Write-Output 'stdout missing'
    }
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    if ($code -lt 0) {
        Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Start-Sleep -Seconds 1
        if (Test-Path -LiteralPath $stdout) {
            $retry = Get-Content -LiteralPath $stdout -Raw -ErrorAction SilentlyContinue
            if ($retry -and $retry -match 'EXIT=(-?\d+)') { $code = [int]$Matches[1] }
            if ($retry) { $text = $retry }
        }
    }
    if ($ExpectText) {
        if (-not $text -or [string]::IsNullOrWhiteSpace($text)) {
            Write-Output 'expect-text: empty stdout'
            return 1
        }
        if ($text -notmatch $ExpectText) {
            Write-Output ('expect-text missed: ' + $ExpectText)
            return 1
        }
    }
    return [int]$code
}

function Invoke-SystemScript {
    param([string]$Title, [string[]]$BodyLines, [int]$WaitSeconds = 45)
    Write-Output ""
    Write-Output ("===== system-script:" + $Title + " =====")
    $stdout = Join-Path $OutDir ("sys_{0}.out" -f $Title)
    $wrapper = Join-Path $env:TEMP ("esptool_smoke_{0}.cmd" -f $Title)
    Remove-Item -LiteralPath $stdout -Force -ErrorAction SilentlyContinue
    $lines = @('@echo off', "cd /d `"$script:Wd`"") + $BodyLines + @(
        "echo EXIT=%ERRORLEVEL% >> `"$stdout`""
    )
    $lines -join "`r`n" | Set-Content -LiteralPath $wrapper -Encoding ASCII
    $task = $script:TaskPrefix + $Title
    Start-SystemCmd $task $wrapper
    [void](Wait-Out $stdout $WaitSeconds)
    $code = -1
    if (Test-Path -LiteralPath $stdout) {
        $text = Get-Content -LiteralPath $stdout -Raw
        if ($text -match 'EXIT=(-?\d+)') { $code = [int]$Matches[1] }
        Get-Content -LiteralPath $stdout |
            Select-String -Pattern 'EXIT=|attribute:|present |absent |error' |
            ForEach-Object { Write-Output $_.Line }
    } else {
        Write-Output 'stdout missing'
    }
    Unregister-ScheduledTask -TaskName $task -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $wrapper -Force -ErrorAction SilentlyContinue
    return [int]$code
}

function Invoke-MonitorTrigger {
    param(
        [string]$Title,
        [string]$RulesPath,
        [string[]]$TriggerLines,
        [int]$DurationMs = 12000,
        [string]$Want = '0',
        [switch]$Iocp,
        [string]$ExpectEvent = '',
        [string]$ExpectEventAny = '',
        [string]$ExpectName = '',
        [string]$ExpectProps = '',
        [hashtable]$Replace = @{},
        [switch]$BindProcessImage,
        [switch]$BindFileObject,
        [switch]$BindRegistry,
        [string]$BindValue = '',
        [string]$BindFileValue = '',
        [string]$BindRegValue = '',
        [int]$MaxNotifications = 20,
        [int]$TriggerDelaySec = 4,
        [string]$ExpectText = ''
    )
    Write-Output ""
    Write-Output ("===== monitor:" + $Title + " =====")
    $monOut = Join-Path $OutDir ("mon_{0}.out" -f $Title)
    $trigOut = Join-Path $OutDir ("trig_{0}.out" -f $Title)
    $monCmd = Join-Path $env:TEMP ("esptool_smoke_mon_{0}.cmd" -f $Title)
    $trigCmd = Join-Path $env:TEMP ("esptool_smoke_trig_{0}.cmd" -f $Title)
    Remove-Item -LiteralPath $monOut, $trigOut -Force -ErrorAction SilentlyContinue
    $bindNote = ''
    $unique = New-UniqueRules -Src $RulesPath -Replace $Replace
    if (-not $unique) {
        Add-Case ("monitor_" + $Title) '0' 1 'monitor' $script:LastRulesError
        return
    }
    $xmlText = [System.IO.File]::ReadAllText($unique)
    $bindKinds = @()
    if ($BindProcessImage) { $bindKinds += @{ Kind = 'process'; Value = $BindValue } }
    if ($BindFileObject) {
        $bindKinds += @{ Kind = 'fileobject'; Value = $(if ($BindFileValue) { $BindFileValue } else { $BindValue }) }
    }
    if ($BindRegistry) {
        $bindKinds += @{ Kind = 'registry'; Value = $(if ($BindRegValue) { $BindRegValue } else { $BindValue }) }
    }
    foreach ($bind in $bindKinds) {
        if (-not $bind.Value) {
            Add-Case ("monitor_" + $Title) '0' 1 'monitor' 'bind-missing-value'
            return
        }
        $bound = Add-UniqueEqualsFilter -XmlText $xmlText -Kind $bind.Kind -Value $bind.Value
        $xmlText = $bound.Text
        if ($bound.Inserted) { $bindNote = 'bind-inserted' }
    }
    if ($bindKinds.Count -gt 0) {
        [System.IO.File]::WriteAllText($unique, $xmlText, [System.Text.UTF8Encoding]::new($false))
    }
    $iocpFlag = $(if ($Iocp) { ' --iocp' } else { '' })
    $waitSec = [int]([Math]::Ceiling($DurationMs / 1000.0) + 18)
    @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "`"$Exe`" --worker monitor --duration $DurationMs --max $MaxNotifications --rules `"$unique`" --no-provision --dll `"$Dll`" --log `"$OutDir\mon_$Title.log`"$iocpFlag > `"$monOut`" 2>&1"
        "echo EXIT=%ERRORLEVEL% >> `"$monOut`""
    ) -join "`r`n" | Set-Content -LiteralPath $monCmd -Encoding ASCII
    $trigBody = @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "echo TRIGGER_START >> `"$trigOut`""
    ) + $TriggerLines + @(
        "echo TRIGGER_DONE >> `"$trigOut`""
    )
    $trigBody -join "`r`n" | Set-Content -LiteralPath $trigCmd -Encoding ASCII
    Start-SystemCmd ($script:TaskPrefix + 'M-' + $Title) $monCmd -NoPsExec
    if ($TriggerDelaySec -lt 1) { $TriggerDelaySec = 1 }
    Start-Sleep -Seconds $TriggerDelaySec
    Start-SystemCmd ($script:TaskPrefix + 'T-' + $Title) $trigCmd -NoPsExec
    [void](Wait-Out $monOut $waitSec)
    $code = -1
    $note = $(if ($bindNote) { $bindNote } else { '' })
    $text = ''
    if (Test-Path -LiteralPath $monOut) {
        $text = Get-Content -LiteralPath $monOut -Raw
        if ($text -match 'EXIT=(-?\d+)') { $code = [int]$Matches[1] }
        if ($text -match 'received (\d+)') { $note = ($note + ' received=' + $Matches[1]).Trim() }
        $events = [regex]::Matches($text, 'event=(\d+)') | ForEach-Object { $_.Groups[1].Value } | Select-Object -Unique
        if ($events) { $note = ($note + ' events=' + ($events -join ',')).Trim() }
        if ($text -match 'pid=(\d+)') { $note = ($note + ' pid=' + $Matches[1]).Trim() }
        if ($text -match 'name=(\S+)') { $note = ($note + ' name=' + $Matches[1]).Trim() }
        if ($text -match 'prop\[([^\]]+)\]') { $note = ($note + ' props=' + $Matches[1]).Trim() }
        if ($text -match 'EspUpdateRules\s+(\S+)') { $note = ($note + ' update=' + $Matches[1]).Trim() }
        Get-Content -LiteralPath $monOut |
            Select-String -Pattern 'EXIT=|received |EspCreateRule|EspUpdateRules|event=|ref created|EspQuery|EspIs|EspCreateProcess|EspCreateFile|EspCreateEvent|not exported|prop\[' |
            ForEach-Object { Write-Output $_.Line }
    }
    Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'M-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'T-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $monCmd, $trigCmd -Force -ErrorAction SilentlyContinue
    if ($Want -eq '0' -and -not $ExpectEvent -and -not $ExpectEventAny -and -not $ExpectName) {
        $code = 1
        $note = ($note + ' unbound-want0').Trim()
    }
    if ($Want -eq '0' -and $ExpectProps) {
        foreach ($prop in ($ExpectProps -split ',')) {
            $pTrim = $prop.Trim()
            if ($pTrim) {
                $propsRx = 'prop\[' + [regex]::Escape($pTrim)
                if ($text -notmatch $propsRx) {
                    $code = 1
                    $note = ($note + ' props-miss:' + $pTrim).Trim()
                }
            }
        }
    }
    if ($Want -eq '0' -and $ExpectEvent) {
        $eventRx = 'event=' + [regex]::Escape($ExpectEvent) + '(\s|$)'
        if ($text -notmatch $eventRx) {
            $code = 1
            $note = ($note + ' event-miss').Trim()
        }
    }
    if ($Want -eq '0' -and $ExpectEventAny) {
        $anyHit = $false
        foreach ($ev in ($ExpectEventAny -split ',')) {
            $eventRx = 'event=' + [regex]::Escape($ev.Trim()) + '(\s|$)'
            if ($text -match $eventRx) { $anyHit = $true; break }
        }
        if (-not $anyHit) {
            $code = 1
            $note = ($note + ' event-miss').Trim()
        }
    }
    if ($Want -eq '0' -and $ExpectName) {
        $nameRx = 'name=\S*' + [regex]::Escape($ExpectName)
        if ($text -notmatch $nameRx) {
            $code = 1
            $note = ($note + ' name-miss').Trim()
        }
    }
    if ($Want -eq '0' -and $ExpectText) {
        if ($text -notlike ('*' + $ExpectText + '*')) {
            $code = 1
            $note = ($note + ' text-miss').Trim()
        }
    }
    Add-Case ("monitor_" + $Title) $Want $code 'monitor' $note
}

function New-PendingTrigger {
    param([string]$Mode, [string]$ObjectName = '')
    $work = Join-Path $OutDir 'pending'
    New-Item -ItemType Directory -Force -Path $work | Out-Null
    $extra = ''
    if ($ObjectName) { $extra = ' -ObjectName "' + $ObjectName + '"' }
    return "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-Pending.ps1`" -WorkDir `"$work`" -Mode $Mode$extra"
}

function Invoke-SerializeRules {
    param([string]$Title, [string]$XmlLeaf, [string]$ExpectUpdate = '0x80070057')
    $src = Join-Path $RulesDir $XmlLeaf
    $unique = New-UniqueRules $src
    if (-not $unique) {
        Add-Case $Title '0' 1 'gap' $script:LastRulesError
        return 1
    }
    $stdout = Join-Path $OutDir ("sys_{0}.out" -f $Title)
    $code = Invoke-SystemEsp $Title "--worker rules --no-provision --dll $Dll --rules $unique" 40
    $note = ''
    if (Test-Path -LiteralPath $stdout) {
        $text = Get-Content -LiteralPath $stdout -Raw
        if ($text -match 'EspCreateRule\S*\s+(\S+)') { $note = ($note + ' create=' + $Matches[1]).Trim() }
        if ($text -match 'EspUpdateRules\s+(\S+)') { $note = ($note + ' update=' + $Matches[1]).Trim() }
    }
    $ok = ($note -match 'create=0x00000000' -and $note -match ('update=' + [regex]::Escape($ExpectUpdate)))
    Add-Case $Title '0' ($(if ($ok) { 0 } else { 1 })) 'gap' $note
    return $code
}

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

function Test-CompatHolderMarker {
    param([string]$Text)
    if (-not $Text) {
        return 'none'
    }
    $patched = ($Text -match 'enforce-compat: rule') -and ($Text -match 'installed via in-memory client patch')
    if ($patched) { return 'patched' }
    if (Test-NamedDenyRefuseMarker $Text) { return 'refused' }
    return 'none'
}

function Invoke-HeldCompatDeny {
    param(
        [string]$Title,
        [string]$RulesPath,
        [hashtable]$Replace = @{},
        [string]$TriggerScript,
        [string]$DeniedPath,
        [string]$ControlPath,
        [string]$ExpectedDeniedHresult,
        [int]$DurationMs = 45000,
        [int]$PollSeconds = 20,
        [int]$PostPatchDelaySec = 3
    )
    Write-Output ""
    Write-Output ("===== compat-deny:" + $Title + " =====")
    $unique = New-UniqueRules -Src $RulesPath -Replace $Replace
    if (-not $unique) {
        Add-Case ($Title + '_compat_logged') '0' 1 'deny' $script:LastRulesError
        return
    }
    $holdOut = Join-Path $OutDir ("hold_{0}.out" -f $Title)
    $denyOut = Join-Path $OutDir ("deny_{0}.out" -f $Title)
    $ctrlOut = Join-Path $OutDir ("ctrl_{0}.out" -f $Title)
    $holdCmd = Join-Path $env:TEMP ("esptool_smoke_hold_{0}.cmd" -f $Title)
    $denyCmd = Join-Path $env:TEMP ("esptool_smoke_deny_{0}.cmd" -f $Title)
    $ctrlCmd = Join-Path $env:TEMP ("esptool_smoke_ctrl_{0}.cmd" -f $Title)
    Remove-Item -LiteralPath $holdOut, $denyOut, $ctrlOut -Force -ErrorAction SilentlyContinue
    $waitSec = [int]([Math]::Ceiling($DurationMs / 1000.0) + 12)
    @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "`"$Exe`" --worker rules --enforce-compat --duration $DurationMs --no-provision --dll `"$Dll`" --rules `"$unique`" > `"$holdOut`" 2>&1"
        "echo EXIT=%ERRORLEVEL% >> `"$holdOut`""
    ) -join "`r`n" | Set-Content -LiteralPath $holdCmd -Encoding ASCII
    Start-SystemCmd ($script:TaskPrefix + 'H-' + $Title) $holdCmd -NoPsExec
    $marker = 'none'
    $deadline = (Get-Date).AddSeconds($PollSeconds)
    $holdText = ''
    do {
        Start-Sleep -Milliseconds 400
        if (Test-Path -LiteralPath $holdOut) {
            $holdText = Get-Content -LiteralPath $holdOut -Raw -ErrorAction SilentlyContinue
            $marker = Test-CompatHolderMarker $holdText
            if ($marker -ne 'none') { break }
        }
    } while ((Get-Date) -lt $deadline)
    if ($marker -eq 'none') {
        Add-Case ($Title + '_compat_logged') '0' 1 'deny' 'compat-marker-miss'
        Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'H-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
        Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $holdCmd -Force -ErrorAction SilentlyContinue
        return
    }
    Add-Case ($Title + '_compat_logged') '0' 0 'deny' $marker
    if ($marker -ne 'patched') {
        Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'H-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
        Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
        Remove-Item -LiteralPath $holdCmd -Force -ErrorAction SilentlyContinue
        return
    }
    if ($PostPatchDelaySec -gt 0) { Start-Sleep -Seconds $PostPatchDelaySec }
    $trigPs = Join-Path $script:Root $TriggerScript
    @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "powershell -NoProfile -ExecutionPolicy Bypass -File `"$trigPs`" -Path `"$DeniedPath`" > `"$denyOut`" 2>&1"
    ) -join "`r`n" | Set-Content -LiteralPath $denyCmd -Encoding ASCII
    Start-SystemCmd ($script:TaskPrefix + 'D-' + $Title) $denyCmd -NoPsExec
    $denyDeadline = (Get-Date).AddSeconds(20)
    $denyText = ''
    do {
        Start-Sleep -Milliseconds 300
        if (Test-Path -LiteralPath $denyOut) {
            $denyText = Get-Content -LiteralPath $denyOut -Raw -ErrorAction SilentlyContinue
            if ($denyText -match 'operation=') { break }
        }
    } while ((Get-Date) -lt $denyDeadline)
    $hrRx = 'operation=DENIED 0x' + [regex]::Escape($ExpectedDeniedHresult)
    $denyGot = $(if ($denyText -imatch $hrRx) { 0 } else { 1 })
    $denyNote = 'operation-miss'
    if ($denyText -imatch 'operation=\S+') { $denyNote = $Matches[0] }
    Add-Case ($Title + '_denied') '0' $denyGot 'deny' $denyNote
    @(
        '@echo off'
        "cd /d `"$script:Wd`""
        "powershell -NoProfile -ExecutionPolicy Bypass -File `"$trigPs`" -Path `"$ControlPath`" > `"$ctrlOut`" 2>&1"
    ) -join "`r`n" | Set-Content -LiteralPath $ctrlCmd -Encoding ASCII
    Start-SystemCmd ($script:TaskPrefix + 'C-' + $Title) $ctrlCmd -NoPsExec
    $ctrlDeadline = (Get-Date).AddSeconds(20)
    $ctrlText = ''
    do {
        Start-Sleep -Milliseconds 300
        if (Test-Path -LiteralPath $ctrlOut) {
            $ctrlText = Get-Content -LiteralPath $ctrlOut -Raw -ErrorAction SilentlyContinue
            if ($ctrlText -match 'operation=') { break }
        }
    } while ((Get-Date) -lt $ctrlDeadline)
    $ctrlGot = $(if ($ctrlText -imatch 'operation=OK') { 0 } else { 1 })
    $ctrlNote = 'operation-miss'
    if ($ctrlText -imatch 'operation=\S+') { $ctrlNote = $Matches[0] }
    Add-Case ($Title + '_negative') '0' $ctrlGot 'deny' $ctrlNote
    [void](Wait-Out $holdOut $waitSec)
    Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'H-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'D-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
    Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'C-' + $Title) -Confirm:$false -ErrorAction SilentlyContinue
    Remove-Item -LiteralPath $holdCmd, $denyCmd, $ctrlCmd -Force -ErrorAction SilentlyContinue
}

$xmlOnDisk = @(Get-ChildItem -LiteralPath $RulesDir -Filter '*.xml')
$manifestPath = Join-Path $script:Root 'rules.manifest.json'
if (-not (Test-Path -LiteralPath $manifestPath)) {
    Add-Case 'xml_rules_present' '0' 1 'coverage' 'manifest-missing'
} else {
    $xmlWant = [int]((Get-Content -LiteralPath $manifestPath -Raw | ConvertFrom-Json).count)
    $xmlPresentCode = $(if ($xmlOnDisk.Count -eq $xmlWant -and $xmlOnDisk.Count -gt 0) { 0 } else { 1 })
    Add-Case 'xml_rules_present' '0' $xmlPresentCode 'coverage' ('have=' + $xmlOnDisk.Count + ' want=' + $xmlWant)
}

Write-Output '=== host facts ==='
$item = Get-Item -LiteralPath $Exe
Write-Output ("exe={0} bytes={1} mtime={2}" -f $Exe, $item.Length, $item.LastWriteTimeUtc)
Write-Output ("dll={0}" -f $Dll)
Write-Output ("rules={0}" -f $RulesDir)
Get-ChildItem -LiteralPath $RulesDir -Filter '*.xml' | ForEach-Object { Write-Output $_.Name }
Write-Output '=== fltmc ==='
fltmc.exe filters
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'esptool-sm*' -or $_.Name -eq 'esptool-smoke-svc' } |
    ForEach-Object {
        Write-Output ("cleanup service " + $_.Name)
        sc.exe stop $_.Name | Out-Null
        sc.exe delete $_.Name | Out-Null
    }
Stop-SmokeTasks

if ($DenyOnly) {
    $code = Invoke-AdminEsp 'help' '--help'
    Add-Case 'cli_help' '0' $code 'cli' '--help'
    $helpText = ''
    $helpOut = Join-Path $OutDir 'admin_help.out'
    if (Test-Path -LiteralPath $helpOut) { $helpText = Get-Content -LiteralPath $helpOut -Raw }
    $compatHelpGot = $(if ($helpText -match '--enforce-compat') { 0 } else { 1 })
    Add-Case 'cli_help_enforce_compat' '0' $compatHelpGot 'cli' '--enforce-compat'
}

if (-not $DenyOnly) {
# ---------------------------------------------------------------------------
# CLI parse and usage
# ---------------------------------------------------------------------------
$code = Invoke-AdminEsp 'help' '--help'
Add-Case 'cli_help' '0' $code 'cli' '--help'
$helpText = ''
$helpOut = Join-Path $OutDir 'admin_help.out'
if (Test-Path -LiteralPath $helpOut) { $helpText = Get-Content -LiteralPath $helpOut -Raw }
$compatHelpGot = $(if ($helpText -match '--enforce-compat') { 0 } else { 1 })
Add-Case 'cli_help_enforce_compat' '0' $compatHelpGot 'cli' '--enforce-compat'
$code = Invoke-AdminEsp 'help_h' '-h'
Add-Case 'cli_help_h' '0' $code 'cli' '-h'
$code = Invoke-AdminEsp 'no_command' ''
Add-Case 'cli_no_command' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'unknown_cmd' 'not-a-command'
Add-Case 'cli_unknown_cmd' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'unknown_opt' 'status --not-an-option'
Add-Case 'cli_unknown_opt' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'helpfulness' 'status --helpfulness'
Add-Case 'cli_helpfulness' '2' $code 'cli' 'must not match --help'
$code = Invoke-AdminEsp 'missing_duration' 'monitor --duration'
Add-Case 'cli_missing_duration' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_dll' 'exports --dll'
Add-Case 'cli_missing_dll' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_rules_eq' 'rules --rules'
Add-Case 'cli_missing_rules' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_max' 'monitor --max'
Add-Case 'cli_missing_max' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_permission' 'connect --permission'
Add-Case 'cli_missing_permission' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_pipe' 'ipc ping --pipe'
Add-Case 'cli_missing_pipe' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_service' 'service install --service'
Add-Case 'cli_missing_service' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_log' 'status --log'
Add-Case 'cli_missing_log' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_level' 'status --level'
Add-Case 'cli_missing_level' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_target' 'status --target'
Add-Case 'cli_missing_target' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_guid' 'unregister --guid'
Add-Case 'cli_missing_guid' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_kind' 'query --kind'
Add-Case 'cli_missing_kind' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_pid' 'refs --pid'
Add-Case 'cli_missing_pid' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_tid' 'refs --tid'
Add-Case 'cli_missing_tid' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_path' 'refs --path'
Add-Case 'cli_missing_path' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_file_id' 'refs --file-id'
Add-Case 'cli_missing_file_id' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_volume' 'refs --volume'
Add-Case 'cli_missing_volume' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_stream' 'refs --stream'
Add-Case 'cli_missing_stream' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_name' 'refs --name'
Add-Case 'cli_missing_name' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_event_id' 'refs --event-id'
Add-Case 'cli_missing_event_id' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_properties' 'query --properties'
Add-Case 'cli_missing_properties' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_supported' 'query --supported'
Add-Case 'cli_missing_supported' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_type' 'collections --type'
Add-Case 'cli_missing_type' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'missing_lifetime' 'collections --lifetime'
Add-Case 'cli_missing_lifetime' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'invalid_type' 'collections --type xyz'
Add-Case 'cli_invalid_type' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'invalid_lifetime' 'collections --lifetime xyz'
Add-Case 'cli_invalid_lifetime' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'invalid_duration' 'monitor --duration xyz'
Add-Case 'cli_invalid_duration' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'invalid_max' 'monitor --max xyz'
Add-Case 'cli_invalid_max' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'conflict_prov_force' 'monitor --no-provision --force-provision'
Add-Case 'cli_conflict_prov_force' '2' $code 'cli' 'rejects --no-provision + --force-provision'
$code = Invoke-AdminEsp 'conflict_prov_perm' 'monitor --no-provision --permission restricted'
Add-Case 'cli_conflict_prov_perm' '2' $code 'cli' 'rejects --no-provision + --permission'
$code = Invoke-AdminEsp 'conflict_hop' 'monitor --no-hop --force-hop'
Add-Case 'cli_conflict_hop' '2' $code 'cli' 'rejects --no-hop + --force-hop'
$code = Invoke-AdminEsp 'dashdash' '-- connect'
Add-Case 'cli_dashdash' '2' $code 'cli' '-- eats the command'
$code = Invoke-AdminEsp 'dll_missing_file' "exports --dll C:\this\does\not\exist\espclient.dll"
Add-Case 'cli_dll_missing_file' '2' $code 'cli' ''
$code = Invoke-AdminEsp 'status_levels_trace' "status --dll $Dll --level TRACE --verbose -v --json --target unused --log $OutDir\status_trace.log"
Add-Case 'cli_status_level_TRACE' '0' $code 'cli' 'EqualsIgnoreCase'
$code = Invoke-AdminEsp 'status_levels_debug' "status --dll $Dll --level DEBUG"
Add-Case 'cli_status_level_DEBUG' '0' $code 'cli' ''
$code = Invoke-AdminEsp 'status_levels_warn' "status --dll $Dll --level warn"
Add-Case 'cli_status_level_warn' '0' $code 'cli' ''
$code = Invoke-AdminEsp 'status_levels_error' "status --dll $Dll --level error"
Add-Case 'cli_status_level_error' '0' $code 'cli' ''
$code = Invoke-AdminEsp 'status_levels_info' "status --dll $Dll --level info"
Add-Case 'cli_status_level_info' '0' $code 'cli' ''
$code = Invoke-AdminEsp 'status_levels_bogus' "status --dll $Dll --level not-a-level"
Add-Case 'cli_status_level_unknown' '0' $code 'cli' 'unknown level stays Info'
$code = Invoke-AdminEsp 'exports_eq' ("exports --dll=" + $Dll)
Add-Case 'cli_exports_equals_dll' '0' $code 'cli' '--flag=value'
$code = Invoke-AdminEsp 'status_log_eq' ("status --dll $Dll --log=" + $OutDir + '\status_log_eq.log')
Add-Case 'cli_status_log_eq' '0' $code 'cli' '--log=value'
$code = Invoke-AdminEsp 'status_level_eq' "status --dll $Dll --level=DEBUG"
Add-Case 'cli_status_level_eq' '0' $code 'cli' '--level=value'
$code = Invoke-AdminEsp 'status_target_eq' "status --dll $Dll --target=unused"
Add-Case 'cli_status_target_eq' '0' $code 'cli' '--target=value'
$code = Invoke-AdminEsp 'exports_admin' "exports --dll $Dll --verbose -v"
Add-Case 'admin_exports' '0' $code 'esp' 'no hop'
$code = Invoke-AdminEsp 'status_admin' "status --dll $Dll"
Add-Case 'admin_status' '0' $code 'esp' 'no hop'

# ---------------------------------------------------------------------------
# ppl / token / provision as admin (denied or local)
# ---------------------------------------------------------------------------
$code = Invoke-AdminEsp 'ppl_missing' 'ppl'
Add-Case 'admin_ppl_missing' '2' $code 'ppl' ''
$code = Invoke-AdminEsp 'ppl_unknown' 'ppl not-a-sub'
Add-Case 'admin_ppl_unknown' '2' $code 'ppl' ''
$code = Invoke-AdminEsp 'ppl_status' 'ppl status'
Add-Case 'admin_ppl_status' '0' $code 'ppl' ''

$code = Invoke-AdminEsp 'token_missing' 'token'
Add-Case 'admin_token_missing' '2' $code 'token' ''
$code = Invoke-AdminEsp 'token_unknown' 'token not-a-sub'
Add-Case 'admin_token_unknown' '1' $code 'token' 'non-status token hops TCB first'
$code = Invoke-AdminEsp 'token_status' 'token status'
Add-Case 'admin_token_status' '0' $code 'token' ''
$code = Invoke-AdminEsp 'token_bad_perm' 'token set not-a-perm'
Add-Case 'admin_token_bad_perm' '1' $code 'token' 'set hops TCB before ParsePermission'
$code = Invoke-AdminEsp 'token_set_denied' 'token set restricted'
Add-Case 'admin_token_set_denied' '1' $code 'token' 'admin lacks SYSTEM+TCB'
$code = Invoke-AdminEsp 'token_clear_denied' 'token clear'
Add-Case 'admin_token_clear_denied' '1' $code 'token' ''

$code = Invoke-AdminEsp 'provision_admin' 'provision'
Add-Case 'admin_provision_hop' '1' $code 'provision' 'hop requires SYSTEM+TCB'
$code = Invoke-AdminEsp 'connect_denied' "connect --dll $Dll"
Add-Case 'admin_connect_hop' '1' $code 'esp' 'hop requires SYSTEM+TCB'
$code = Invoke-AdminEsp 'query_denied' "query --dll $Dll"
Add-Case 'admin_query_hop' '1' $code 'esp' ''
$code = Invoke-AdminEsp 'refs_denied' "refs process --dll $Dll"
Add-Case 'admin_refs_hop' '1' $code 'esp' ''
$code = Invoke-AdminEsp 'collections_denied' "collections --dll $Dll"
Add-Case 'admin_collections_hop' '1' $code 'esp' ''
$code = Invoke-AdminEsp 'context_denied' "context --dll $Dll"
Add-Case 'admin_context_hop' '1' $code 'esp' ''
$code = Invoke-AdminEsp 'monitor_denied' "monitor --duration 1500 --dll $Dll"
Add-Case 'admin_monitor_hop' '1' $code 'monitor' ''
$code = Invoke-AdminEsp 'exercise_denied' "exercise --dll $Dll"
Add-Case 'admin_exercise_hop' '1' $code 'esp' ''
$code = Invoke-AdminEsp 'clients_denied' "clients --dll $Dll"
Add-Case 'admin_clients_hop' '1' $code 'session' 'hop requires SYSTEM+TCB'
$code = Invoke-AdminEsp 'unregister_denied' 'unregister --guid 00000000-0000-0000-0000-000000000000'
Add-Case 'admin_unregister_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'enum_rules_denied' "enum-rules --dll $Dll"
Add-Case 'admin_enum_rules_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'remove_rules_denied' "remove-rules --dll $Dll"
Add-Case 'admin_remove_rules_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'persist_denied' "persist-rules --dll $Dll --rules $RulesDir\persist_process_create_empty_deny.xml"
Add-Case 'admin_persist_rules_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'open_queue_denied' "open-queue --dll $Dll"
Add-Case 'admin_open_queue_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'trust_denied' "trust --dll $Dll"
Add-Case 'admin_trust_hop' '1' $code 'session' ''
$code = Invoke-AdminEsp 'call_one_missing' 'call-one'
Add-Case 'admin_call_one_missing' '1' $code 'esp' 'hop requires SYSTEM before missing-name 2'
# call-one without name: EnsureWorkerOrTcb hops first, so admin gets 1 not 2.
# Re-run with --worker so parse/dispatch reaches RunCallOne.
$code = Invoke-AdminEsp 'call_one_missing_worker' '--worker call-one'
Add-Case 'admin_call_one_missing_worker' '1' $code 'esp' '--worker skips hop; PrepareThisProcess still requires SYSTEM'

$code = Invoke-AdminEsp 'rules_missing' 'rules'
Add-Case 'admin_rules_missing_hop' '1' $code 'rules' 'hop first'
$code = Invoke-AdminEsp 'ipc_missing' 'ipc'
Add-Case 'admin_ipc_missing' '2' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_unknown' 'ipc not-a-sub'
Add-Case 'admin_ipc_unknown' '2' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_ping_noserver' 'ipc ping'
Add-Case 'admin_ipc_ping_noserver' '1' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_status_noserver' 'ipc status'
Add-Case 'admin_ipc_status_noserver' '1' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_exports_noserver' 'ipc exports'
Add-Case 'admin_ipc_exports_noserver' '1' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_exercise_noserver' 'ipc exercise'
Add-Case 'admin_ipc_exercise_noserver' '1' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_rules_nopath' 'ipc rules'
Add-Case 'admin_ipc_rules_nopath' '2' $code 'ipc' ''
$code = Invoke-AdminEsp 'service_missing' 'service'
Add-Case 'admin_service_missing' '2' $code 'service' ''
$code = Invoke-AdminEsp 'service_unknown' 'service not-a-sub'
Add-Case 'admin_service_unknown' '2' $code 'service' ''

# ---------------------------------------------------------------------------
# SYSTEM: token lifecycle in one process, provision, hop vs worker
# ---------------------------------------------------------------------------
$code = Invoke-SystemEsp 'call_one_missing' '--worker call-one' 20
Add-Case 'sys_call_one_missing' '2' $code 'esp' ''

$code = Invoke-SystemEsp 'token_unknown' 'token not-a-sub' 20
Add-Case 'sys_token_unknown' '2' $code 'token' ''
$code = Invoke-SystemEsp 'token_bad_perm' 'token set not-a-perm' 20
Add-Case 'sys_token_bad_perm' '2' $code 'token' ''
$code = Invoke-SystemEsp 'token_set_r' 'token set restricted' 20
Add-Case 'sys_token_set_restricted' '0' $code 'token' ''
$code = Invoke-SystemEsp 'token_set_full' 'token set full' 20
Add-Case 'sys_token_set_full' '0' $code 'token' ''
$code = Invoke-SystemEsp 'token_set_default' 'token set' 20
Add-Case 'sys_token_set_default' '0' $code 'token' 'ResolvePermission default'
$code = Invoke-SystemEsp 'token_set_perm_eq' '--permission=restricted token set' 20
Add-Case 'sys_token_set_permission_eq' '0' $code 'token' 'option form, no positional'
$code = Invoke-SystemEsp 'token_set_perm_sp' '--permission restricted token set' 20
Add-Case 'sys_token_set_permission_space' '0' $code 'token' 'space-separated option'
$code = Invoke-SystemEsp 'token_set_perm_full_eq' '--permission=full token set' 20
Add-Case 'sys_token_set_permission_full_eq' '0' $code 'token' ''
$code = Invoke-SystemEsp 'token_clear_fresh' 'token clear' 20
Add-Case 'sys_token_clear_fresh' '1' $code 'token' 'claim is per-process; absent is 0xC0000225'

$code = Invoke-SystemEsp 'provision_noprov_fresh' '--worker provision --no-provision' 20
Add-Case 'sys_provision_noprov_fresh' '1' $code 'provision' 'absent claim is exit 1'

$code = Invoke-SystemScript 'provision_after_set' @(
    "`"$Exe`" token set restricted > `"$OutDir\sys_provision_after_set.out`" 2>&1"
    "if errorlevel 1 goto done"
    "`"$Exe`" --worker provision --permission restricted >> `"$OutDir\sys_provision_after_set.out`" 2>&1"
    ':done'
) 30
Add-Case 'sys_provision_after_set' '0' $code 'provision' ''

$code = Invoke-SystemEsp 'unregister_all' "--worker unregister --all --no-provision --dll $Dll" 120
Add-Case 'sys_unregister_all' '0' $code 'session' 'clear leftover registered clients'
$code = Invoke-SystemEsp 'exports' "--worker exports --dll $Dll --verbose --log $OutDir\exports.log" 30 -ExpectText 'resolved [1-9][0-9]* of [1-9][0-9]*'
Add-Case 'sys_exports' '0' $code 'esp' 'resolved N of M'
$code = Invoke-SystemEsp 'status' "--worker status --dll $Dll --level info" 30 -ExpectText 'dll:'
Add-Case 'sys_status' '0' $code 'esp' 'dll: line'
$code = Invoke-SystemEsp 'connect_noprov' "--worker connect --no-provision --dll $Dll --log $OutDir\connect_np.log" 40 -ExpectText 'ok\s+EspConnectClient\s+0x00000000'
Add-Case 'sys_connect_noprov' '0' $code 'esp' 'after unregister-all'
$code = Invoke-SystemEsp 'connect_restricted' "--worker connect --permission restricted --dll $Dll" 40
Add-Case 'sys_connect_restricted' '1' $code 'esp' 'present claim: Register 0x80070057'
$code = Invoke-SystemEsp 'connect_full' "--worker connect --permission full --dll $Dll" 40
Add-Case 'sys_connect_full' '1' $code 'esp' 'present claim: Register 0x80070057'
$code = Invoke-SystemEsp 'hop_connect_noprov' "connect --no-provision --dll $Dll --log $OutDir\hop_connect.log" 50 -ExpectText 'ok\s+EspConnectClient\s+0x00000000'
Add-Case 'sys_hop_connect_noprov' '0' $code 'esp' 'hop forwards --log; after unregister-all'
$code = Invoke-SystemEsp 'hop_connect_auto' "connect --dll $Dll --log $OutDir\hop_connect_auto.log" 50 -ExpectText 'ok\s+EspConnectClient\s+0x00000000'
Add-Case 'sys_hop_connect_auto' '0' $code 'esp' 'auto-no-provision on test-signing without manual flags'
$code = Invoke-SystemEsp 'hop_connect_perm' "connect --permission restricted --dll $Dll" 50
Add-Case 'sys_hop_connect_permission' '1' $code 'esp' 'hop forwards --permission; Register 0x80070057'
$code = Invoke-SystemEsp 'hop_provision' 'provision' 40
Add-Case 'sys_hop_provision' '0' $code 'provision' 'hop stamps then RunProvision'
$code = Invoke-SystemEsp 'query' "--worker query --no-provision --dll $Dll" 40
Add-Case 'sys_query' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'hop_query' "query --no-provision --dll $Dll" 50
Add-Case 'sys_hop_query' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs' "--worker refs process --pid self --no-provision --dll $Dll" 40
Add-Case 'sys_refs' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'hop_refs' "refs process --pid self --no-provision --dll $Dll" 50
Add-Case 'sys_hop_refs' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'collections' "--worker collections --no-provision --dll $Dll" 40
Add-Case 'sys_collections' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'hop_collections' "collections --no-provision --dll $Dll" 50
Add-Case 'sys_hop_collections' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_nokind' '--worker refs --no-provision' 20
Add-Case 'sys_refs_missing_kind' '1' $code 'esp' 'refs requires a kind'
$code = Invoke-SystemEsp 'refs_props' "--worker refs process --pid self --properties 6 --supported 6 --no-provision --dll $Dll" 40
Add-Case 'sys_refs_props' '0' $code 'esp' 'create plus query and support probe'
$code = Invoke-SystemEsp 'refs_dup' "--worker refs process --pid self --duplicate --context-enum --no-provision --dll $Dll" 40
Add-Case 'sys_refs_duplicate' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_file' "--worker refs file --path C:\Windows\System32\ntdll.dll --no-provision --dll $Dll" 40
Add-Case 'sys_refs_file' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_reg' "--worker refs registry --path HKLM\Software --no-provision --dll $Dll" 40
Add-Case 'sys_refs_registry' '0' $code 'esp' 'kind-1 descriptor; EnsureNtRegistryPath'
$code = Invoke-SystemEsp 'refs_thread' "--worker refs thread --tid self --no-provision --dll $Dll" 40
Add-Case 'sys_refs_thread' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_desktop' "--worker refs desktop --name Default --no-provision --dll $Dll" 40
Add-Case 'sys_refs_desktop' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_ptok' "--worker refs process-token --pid self --no-provision --dll $Dll" 40
Add-Case 'sys_refs_process_token' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_ttok' "--worker refs token --tid self --no-provision --dll $Dll" 40
Add-Case 'sys_refs_thread_token' '1' $code 'esp' 'SYSTEM task thread has no impersonation token (0x8007051D)'
$code = Invoke-SystemEsp 'refs_stream' "--worker refs stream --path C:\Windows\System32\ntdll.dll --no-provision --dll $Dll" 40
Add-Case 'sys_refs_stream' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'refs_from_notify_norules' '--worker refs event --from-notify --no-provision' 20
Add-Case 'sys_refs_from_notify_norules' '1' $code 'esp' '--from-notify requires --rules'
$fromNotify = New-UniqueRules (Join-Path $RulesDir 'monitor_process_create_query_process.xml')
$code = Invoke-SystemEsp 'refs_from_notify' "--worker refs event --from-notify --rules $fromNotify --duration 12000 --max 1 --no-provision --dll $Dll" 40
Add-Case 'sys_refs_from_notify' '0' $code 'esp' 'ProcessCreate spawn then EspCreateEventObjectReferenceById'
$fromNotifyFo = New-UniqueRules (Join-Path $RulesDir 'monitor_fo_create_query_fileobject.xml')
$code = Invoke-SystemEsp 'refs_from_notify_fo' "--worker refs event --from-notify --rules $fromNotifyFo --duration 12000 --max 1 --no-provision --dll $Dll" 40
Add-Case 'sys_refs_from_notify_fo' '0' $code 'esp' 'FoCreate temp file then ByPath or fallback'
$code = Invoke-SystemEsp 'query_kind_proc' "--worker query --kind process --pid self --properties 6 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_process' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'query_kind_tok' "--worker query --kind token --pid self --supported 6 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_token' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'query_kind_stream' "--worker query --kind stream --path C:\Windows\System32\ntdll.dll --supported 1 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_stream' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'query_kind_event' "--worker query --kind event --supported 1 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_event' '0' $code 'esp' 'EspQueryEventProperties is not exported'
$code = Invoke-SystemEsp 'query_kind_event_nosup' "--worker query --kind event --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_event_nosup' '1' $code 'esp' 'event without --supported is exit 1'
$code = Invoke-SystemEsp 'query_kind_ktm' "--worker query --kind ktm --supported 1 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_ktm' '0' $code 'esp' 'no create export'
$code = Invoke-SystemEsp 'query_kind_client' "--worker query --kind client --supported 1 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_client' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'query_kind_client_noprops' "--worker query --kind client --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_client_noprops' '1' $code 'esp' 'client requires --properties or --supported'
$code = Invoke-SystemEsp 'query_kind_rko' "--worker query --kind registry-key-object --supported 1 --no-provision --dll $Dll" 40
Add-Case 'sys_query_kind_rko' '0' $code 'esp' 'no create export'
$code = Invoke-SystemEsp 'coll_type1' "--worker collections --type 1 --no-provision --dll $Dll" 40
Add-Case 'sys_collections_type1' '0' $code 'esp' 'integer create'
$code = Invoke-SystemEsp 'coll_type2_enum' "--worker collections --type 2 --enum-ids --lifetime 1 --open --no-provision --dll $Dll" 40
Add-Case 'sys_collections_type2_enum_open' '0' $code 'esp' 'string create, enum-ids, open same session'
$code = Invoke-SystemEsp 'coll_type3' "--worker collections --type 3 --no-provision --dll $Dll" 40
Add-Case 'sys_collections_type3' '0' $code 'esp' 'binary create'
$code = Invoke-SystemEsp 'context' "--worker context --no-provision --dll $Dll" 40
Add-Case 'sys_context' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'hop_context' "context --no-provision --dll $Dll" 50
Add-Case 'sys_hop_context' '0' $code 'esp' ''
$code = Invoke-SystemEsp 'call_one_unknown' "--worker call-one NotAnEspExport --no-provision --dll $Dll" 30
Add-Case 'sys_call_one_unknown' 'nz' $code 'esp' 'kModNotFound'
$eqIdle = New-UniqueRules (Join-Path $RulesDir 'filter_process_create_process_ntpath.xml') @{
    'C:\Windows\System32\cmd.exe' = 'C:\Windows\System32\esptool-idle-no-such.exe'
}
if (-not $eqIdle) {
    Add-Case 'sys_monitor_equals_flags' '0' 1 'monitor' $script:LastRulesError
} else {
    $code = Invoke-SystemEsp 'duration_eq' "--worker monitor --duration=1500 --max=2 --rules=$eqIdle --no-provision --dll $Dll" 25
    Add-Case 'sys_monitor_equals_flags' '1' $code 'monitor' '--duration= and --max=; idle filter is exit 1'
}

# ---------------------------------------------------------------------------
# rules: every XML
# ---------------------------------------------------------------------------
$code = Invoke-SystemEsp 'rules_missing' '--worker rules --no-provision' 20
Add-Case 'sys_rules_missing' '1' $code 'rules' ''

$badEvent = New-UniqueRules (Join-Path $RulesDir 'fixture_process_create_process_bad_eventtype.xml')
if (-not $badEvent) {
    Add-Case 'sys_rules_fixture_process_create_process_bad_eventtype' '0' 1 'rules' $script:LastRulesError
} else {
    $code = Invoke-SystemEsp 'rules_bad_eventtype' "--worker rules --no-provision --rules $badEvent --dll $Dll" 40
    Add-Case 'sys_rules_fixture_process_create_process_bad_eventtype' '1' $code 'rules' 'EspUpdateRules reject'
}
$badGuid = New-UniqueRules (Join-Path $RulesDir 'fixture_collection_open_missing_guid.xml')
if (-not $badGuid) {
    Add-Case 'sys_rules_fixture_collection_open_missing_guid' '0' 1 'rules' $script:LastRulesError
} else {
    $code = Invoke-SystemEsp 'rules_bad_guid' "--worker rules --no-provision --rules $badGuid --dll $Dll" 40
    Add-Case 'sys_rules_fixture_collection_open_missing_guid' '1' $code 'rules' 'open collection without guid'
}

$hopRules = New-UniqueRules (Join-Path $RulesDir 'monitor_process_create.xml')
$code = Invoke-SystemEsp 'hop_rules' "rules --no-provision --rules $hopRules --dll $Dll" 50 -ExpectText 'ok\s+EspUpdateRules\s+0x00000000'
Add-Case 'sys_hop_rules' '0' $code 'rules' 'LaunchWorker forwards --rules'
$eqRules = New-UniqueRules (Join-Path $RulesDir 'monitor_process_create.xml')
$code = Invoke-SystemEsp 'rules_eq' "--worker rules --no-provision --rules=$eqRules --dll $Dll" 40 -ExpectText 'ok\s+EspUpdateRules\s+0x00000000'
Add-Case 'sys_rules_equals' '0' $code 'rules' '--rules=value'

# ---------------------------------------------------------------------------
# monitor
# ---------------------------------------------------------------------------
$script:Trig = New-TriggerImage
$script:ProcReplace = @{
    '$nt:C:\Windows\System32\cmd.exe' = $script:Trig.NtFilter
    '*cmd.exe'                       = ('*' + $script:Trig.Leaf)
}
$script:TrigCmd = $script:Trig.CmdLine
$regCreate = New-RegProbe
$regQuery = New-RegProbe
$regNt = New-RegProbe
$regQk = New-RegProbe
$regEk = New-RegProbe
$regDel = New-RegProbe
$regQv = New-RegProbe
$foEqLeaf = 'esptool-sm-fo-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.bin'
$foEqPath = Join-Path $OutDir $foEqLeaf
$foNegLeaf = 'esptool-sm-fo-neg-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.bin'
$foNegPath = Join-Path $OutDir $foNegLeaf

Invoke-MonitorTrigger -Title 'process_create' -RulesPath (Join-Path $RulesDir 'monitor_process_create.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6,Process:20,Process:1,Process:2'

$code = Invoke-SystemEsp 'monitor_idle' "--worker monitor --duration 1500 --max 2 --rules $RulesDir\monitor_process_create.xml --no-provision --dll $Dll" 20
Add-Case 'sys_monitor_idle' '1' $code 'monitor' 'zero notifications is exit 1'
$code = Invoke-SystemEsp 'hop_monitor_idle' "monitor --duration 1500 --max 2 --rules $RulesDir\monitor_process_create.xml --no-provision --dll $Dll" 25
Add-Case 'sys_hop_monitor_idle' '1' $code 'monitor' 'hop preserves duration/max/rules'

Invoke-MonitorTrigger -Title 'proc_ntpath' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_ntpath.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000' -ExpectProps 'Process:6,Process:20'
Invoke-MonitorTrigger -Title 'reg_create' -RulesPath (Join-Path $RulesDir 'monitor_reg_create.xml') -TriggerLines @(
    ("reg add " + $regCreate.Hklm + ' /f')
    ("reg delete " + $regCreate.Hklm + ' /f')
) -Want '0' -BindRegistry -BindValue $regCreate.NtMachine -ExpectEvent '7000' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'query_registry' -RulesPath (Join-Path $RulesDir 'monitor_reg_create_query_registry.xml') -TriggerLines @(
    ("reg add " + $regQuery.Hklm + ' /f')
    ("reg delete " + $regQuery.Hklm + ' /f')
) -Want '0' -BindRegistry -BindValue $regQuery.NtMachine -ExpectEvent '7000' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_ntpath' -RulesPath (Join-Path $RulesDir 'filter_reg_create_registry_key_ntpath.xml') -TriggerLines @(
    ("reg add " + $regNt.Hklm + ' /f')
    ("reg delete " + $regNt.Hklm + ' /f')
) -Want '0' -Replace @{ '\REGISTRY\MACHINE\SOFTWARE\esptool_gap_probe' = $regNt.NtMachine } -ExpectEvent '7000' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_querykey' -RulesPath (Join-Path $RulesDir 'monitor_reg_querykey.xml') -TriggerLines @(
    ("reg add " + $regQk.Hklm + ' /f')
    ("reg query " + $regQk.Hklm)
    ("reg delete " + $regQk.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7009' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_enumkey' -RulesPath (Join-Path $RulesDir 'monitor_reg_enumkey.xml') -TriggerLines @(
    ("reg add " + $regEk.Hklm + ' /f')
    ("reg query " + $regEk.Hklm + ' /k')
    ("reg delete " + $regEk.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7013' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'thread_start' -RulesPath (Join-Path $RulesDir 'monitor_thread_start.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '2' -ExpectProps 'Thread:1'
Invoke-MonitorTrigger -Title 'ob_dup' -RulesPath (Join-Path $RulesDir 'monitor_ob_dup.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-ThreadHandle.ps1`""
) -Want '0' -ExpectEvent '8001'
Invoke-MonitorTrigger -Title 'fs_dir' -RulesPath (Join-Path $RulesDir 'monitor_fs_dir.xml') -TriggerLines @(
    ('dir "' + $script:Trig.Path + '"')
) -Want '0' -ExpectEvent '3004'
Invoke-MonitorTrigger -Title 'iocp_process' -RulesPath (Join-Path $RulesDir 'monitor_process_create.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Iocp -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6,Process:20,Process:1'
Invoke-MonitorTrigger -Title 'thread_term' -RulesPath (Join-Path $RulesDir 'monitor_thread_terminate.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '3'
Invoke-MonitorTrigger -Title 'reg_delete' -RulesPath (Join-Path $RulesDir 'monitor_reg_delete.xml') -TriggerLines @(
    ("reg add " + $regDel.Hklm + ' /f')
    ("reg delete " + $regDel.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7002' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'reg_queryvalue' -RulesPath (Join-Path $RulesDir 'monitor_reg_queryvalue.xml') -TriggerLines @(
    ("reg add " + $regQv.Hklm + ' /v Smoke /t REG_SZ /d 1 /f')
    ("reg query " + $regQv.Hklm + ' /v Smoke')
    ("reg delete " + $regQv.Hklm + ' /f')
) -Want '0' -TriggerDelaySec 1 -ExpectEvent '7010' -ExpectProps 'Registry:1'
Invoke-MonitorTrigger -Title 'filter_process_create_process_collection' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_collection.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_process_collection_named' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_collection_named.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_process_collection_integer' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_collection_integer.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'filter_process_create_process_collection_binary' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_collection_binary.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'query_process' -RulesPath (Join-Path $RulesDir 'monitor_process_create_query_process.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6,Process:20'
Invoke-MonitorTrigger -Title 'query_event' -RulesPath (Join-Path $RulesDir 'monitor_process_create_query_event.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'query_token' -RulesPath (Join-Path $RulesDir 'monitor_process_create_query_token.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'query_client' -RulesPath (Join-Path $RulesDir 'monitor_process_create_query_client.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'and_process' -RulesPath (Join-Path $RulesDir 'filter_process_create_and_process.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1' -Replace $script:ProcReplace
Invoke-MonitorTrigger -Title 'xor_process' -RulesPath (Join-Path $RulesDir 'filter_process_create_xor_process.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'process_ntpath_ne' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_ntpath_ne.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'process_pattern' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_pattern.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -Replace $script:ProcReplace -ExpectEvent '1000'
Invoke-MonitorTrigger -Title 'process_implicit_and' -RulesPath (Join-Path $RulesDir 'filter_process_create_process_implicit_and.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1' -Replace $script:ProcReplace
$trioFo = Join-Path $OutDir ('esptool-sm-trio-' + [guid]::NewGuid().ToString('N').Substring(0, 8) + '.txt')
$trioReg = New-RegProbe
Invoke-MonitorTrigger -Title 'create_trio_named' -RulesPath (Join-Path $RulesDir 'monitor_create_trio_named.xml') -TriggerLines @(
    $script:TrigCmd
    ('echo smoke> "' + $trioFo + '"')
    ('reg add ' + $trioReg.Hklm + ' /f')
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -BindFileObject -BindFileValue ('$nt:' + $trioFo) -BindRegistry -BindRegValue $trioReg.NtMachine -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'query_process_token' -RulesPath (Join-Path $RulesDir 'monitor_process_create_query_process_token.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -BindProcessImage -BindValue $script:Trig.NtFilter -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'process_type0' -RulesPath (Join-Path $RulesDir 'monitor_process_create_type0.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '0' -ExpectEvent '1000' -ExpectProps 'Process:6'
Invoke-MonitorTrigger -Title 'fo_equals_win32' -RulesPath (Join-Path $RulesDir 'filter_fo_create_fileobject_equals.xml') -TriggerLines @(
    "powershell -NoProfile -ExecutionPolicy Bypass -File `"$script:Root\Trigger-CreateNew.ps1`" -Path `"$foEqPath`""
) -Want '0' -Replace @{ 'REPLACE_FO_EQUALS' = ('$nt:' + $foEqPath) } -ExpectEvent '2000' -ExpectName $foEqLeaf
Invoke-MonitorTrigger -Title 'fo_equals_neg' -RulesPath (Join-Path $RulesDir 'filter_fo_create_fileobject_equals.xml') -TriggerLines @(
    $script:TrigCmd
) -Want '1' -Replace @{ 'REPLACE_FO_EQUALS' = ('$nt:' + $foNegPath) }
$code = Invoke-SystemEsp 'trust' "--worker trust --no-provision --dll $Dll" 20
Add-Case 'sys_trust' '0' $code 'session' 'connect-tier'
$code = Invoke-SystemEsp 'open_queue' "--worker open-queue --no-provision --dll $Dll" 20 -ExpectText 'open-queue ok'
Add-Case 'sys_open_queue' '0' $code 'session' ''
$code = Invoke-SystemEsp 'unregister_nopath' '--worker unregister --no-provision' 20
Add-Case 'sys_unregister_missing_guid' '2' $code 'session' 'unregister requires --guid'
$code = Invoke-SystemEsp 'unregister_bad' '--worker unregister --no-provision --guid not-a-guid' 20
Add-Case 'sys_unregister_bad_guid' '2' $code 'session' ''
$code = Invoke-SystemEsp 'unregister_eq' "--worker unregister --no-provision --guid=00000000-0000-0000-0000-000000000000 --dll $Dll" 20
Add-Case 'sys_unregister_zero_guid_eq' 'nz' $code 'session' '--guid=value; unknown client'
$code = Invoke-SystemEsp 'unregister_zero' "--worker unregister --no-provision --guid 00000000-0000-0000-0000-000000000000 --dll $Dll" 20
Add-Case 'sys_unregister_zero_guid' 'nz' $code 'session' ''
$code = Invoke-SystemEsp 'hop_trust' "trust --no-provision --dll $Dll" 30
Add-Case 'sys_hop_trust' '0' $code 'session' ''
$code = Invoke-SystemEsp 'hop_enum_rules' "enum-rules --no-provision --dll $Dll" 30
Add-Case 'sys_hop_enum_rules' '0' $code 'session' ''
$code = Invoke-SystemEsp 'hop_open_queue' "open-queue --no-provision --dll $Dll" 30
Add-Case 'sys_hop_open_queue' '0' $code 'session' ''
$code = Invoke-SystemEsp 'collections_session' "--worker collections --no-provision --dll $Dll" 20
Add-Case 'sys_collections_session' '0' $code 'session' 'string collection count 1'
$code = Invoke-SystemEsp 'unregister_before_persist' "--worker unregister --all --no-provision --dll $Dll" 120
Add-Case 'sys_unregister_before_persist' '0' $code 'session' 'clear leftover clients before persist'
$persistRules = New-UniqueRules (Join-Path $RulesDir 'persist_process_create_empty_deny.xml')
$code = Invoke-SystemEsp 'persist_process_create_empty_deny' "--worker persist-rules --no-provision --rules $persistRules --dll $Dll" 40 -ExpectText 'persist-rules [1-9][0-9]*'
Add-Case 'sys_persist_rules' '0' $code 'session' 'lifetime FFI 3'
$code = Invoke-SystemEsp 'persist_missing' '--worker persist-rules --no-provision' 20
Add-Case 'sys_persist_rules_missing' '1' $code 'session' 'persist-rules requires --rules'
$code = Invoke-SystemEsp 'hop_persist' "persist-rules --no-provision --rules $persistRules --dll $Dll" 50 -ExpectText 'persist-rules [1-9][0-9]*'
Add-Case 'sys_hop_persist_rules' '0' $code 'session' ''
$code = Invoke-SystemEsp 'clients' "--worker clients --no-provision --dll $Dll" 20 -ExpectText 'registered-clients [1-9][0-9]*'
Add-Case 'sys_clients' '0' $code 'session' 'after persist-rules'
$code = Invoke-SystemEsp 'hop_clients' "clients --no-provision --dll $Dll" 30 -ExpectText 'registered-clients [1-9][0-9]*'
Add-Case 'sys_hop_clients' '0' $code 'session' 'after persist-rules'
$code = Invoke-SystemEsp 'unregister_after_persist' "--worker unregister --all --no-provision --dll $Dll" 120
Add-Case 'sys_unregister_after_persist' '0' $code 'session' ''
$code = Invoke-SystemEsp 'clients_cleared' "--worker clients --no-provision --dll $Dll" 20 -ExpectText 'registered-clients 0'
Add-Case 'sys_clients_cleared' '0' $code 'session' 'after unregister --all'
$code = Invoke-SystemEsp 'enum_rules' "--worker enum-rules --no-provision --dll $Dll" 20
Add-Case 'sys_enum_rules' '0' $code 'session' ''
$code = Invoke-SystemEsp 'remove_rules' "--worker remove-rules --no-provision --dll $Dll" 20
Add-Case 'sys_remove_rules' '0' $code 'session' ''
$code = Invoke-SystemEsp 'hop_remove_rules' "remove-rules --no-provision --dll $Dll" 30
Add-Case 'sys_hop_remove_rules' '0' $code 'session' ''

# ---------------------------------------------------------------------------
# gap cases
# ---------------------------------------------------------------------------
$gapScript = Join-Path $script:Root 'Invoke-EsptoolGapCases.ps1'
if (-not (Test-Path -LiteralPath $gapScript)) {
    Write-Error ("gap cases script missing: {0}" -f $gapScript)
    exit 2
}
. $gapScript

$xmlCoverageScript = Join-Path $script:Root 'Invoke-EsptoolXmlCoverage.ps1'
if (-not (Test-Path -LiteralPath $xmlCoverageScript)) {
    Write-Error ("xml coverage script missing: {0}" -f $xmlCoverageScript)
    exit 2
}
. $xmlCoverageScript
}

if (-not $DenyOnly) {
# ---------------------------------------------------------------------------
# exercise
# ---------------------------------------------------------------------------
Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
$code = Invoke-SystemEsp 'exercise' "--worker exercise --no-provision --dll $Dll --log $OutDir\exercise.log" 240
Add-Case 'sys_exercise' '0' $code 'esp' ''
if (-not $SkipIsolated) {
    Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
    $code = Invoke-SystemEsp 'exercise_iso' "--worker exercise --isolated --no-provision --dll $Dll --log $OutDir\exercise_iso.log" 240
    Add-Case 'sys_exercise_isolated' '0' $code 'esp' 'one child per export'
}

# ---------------------------------------------------------------------------
# service + ipc
# ---------------------------------------------------------------------------
Get-Service -ErrorAction SilentlyContinue |
    Where-Object { $_.Name -like 'esptool-sm*' -or $_.Name -eq 'esptool-smoke-svc' } |
    ForEach-Object {
        sc.exe stop $_.Name | Out-Null
        sc.exe delete $_.Name | Out-Null
    }
$svc = 'esptool-sm-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$pipe = $svc
$code = Invoke-AdminEsp 'svc_install' "--service $svc --no-provision service install"
Add-Case 'admin_service_install' '0' $code 'service' 'ImagePath gets --no-provision'
$imgNoprov = ''
try {
    $imgNoprov = [string](Get-CimInstance Win32_Service -Filter "Name='$svc'").PathName
} catch {
    $imgNoprov = ''
}
if ($imgNoprov -match '--no-provision') {
    Add-Case 'admin_service_imagepath_noprov' '0' 0 'service' $imgNoprov
} else {
    Add-Case 'admin_service_imagepath_noprov' '0' 1 'service' $imgNoprov
}
$code = Invoke-SystemEsp 'svc_uninstall_clean' "--service $svc service uninstall" 20
Add-Case 'sys_service_uninstall_clean' '0' $code 'service' 'before protect'
$code = Invoke-AdminEsp 'svc_install2' "--service $svc --no-provision service install"
Add-Case 'admin_service_reinstall' '0' $code 'service' 'reinstall after clean uninstall'
$code = Invoke-AdminEsp 'svc_install_dup' "--service $svc --no-provision service install"
Add-Case 'admin_service_install_dup' '1' $code 'service' 'already exists'
$svcEq = 'esptool-sm-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$code = Invoke-AdminEsp 'svc_install_eq' ("--service=" + $svcEq + ' --no-provision service install')
Add-Case 'admin_service_equals_name' '0' $code 'service' '--service=value'
sc.exe stop $svcEq | Out-Null
sc.exe delete $svcEq | Out-Null
$svcProv = 'esptool-sm-' + [guid]::NewGuid().ToString('N').Substring(0, 8)
$code = Invoke-AdminEsp 'svc_install_prov' "--service $svcProv service install"
Add-Case 'admin_service_install_provision' '0' $code 'service' 'ImagePath omits --no-provision'
$img = ''
try {
    $img = [string](Get-CimInstance Win32_Service -Filter "Name='$svcProv'").PathName
} catch {
    $img = ''
}
if ($img -match '--no-provision') {
    Add-Case 'admin_service_imagepath_provision' '0' 1 'service' $img
} else {
    Add-Case 'admin_service_imagepath_provision' '0' 0 'service' $img
}
sc.exe stop $svcProv | Out-Null
sc.exe delete $svcProv | Out-Null

$fgOut = Join-Path $OutDir 'svc_foreground.out'
$fgCmd = Join-Path $env:TEMP 'esptool_smoke_fg.cmd'
Remove-Item -LiteralPath $fgOut -Force -ErrorAction SilentlyContinue
@(
    '@echo off'
    "cd /d `"$script:Wd`""
    "`"$Exe`" --service $svc --pipe $svc-ignored --no-provision service foreground > `"$fgOut`" 2>&1"
    "echo EXIT=%ERRORLEVEL% >> `"$fgOut`""
) -join "`r`n" | Set-Content -LiteralPath $fgCmd -Encoding ASCII
Start-SystemCmd ($script:TaskPrefix + 'fg') $fgCmd
Start-Sleep -Seconds 4
$code = Invoke-AdminEsp 'ipc_ping' "--pipe $pipe ipc ping"
Add-Case 'admin_ipc_ping' '0' $code 'ipc' 'foreground listens on --service name'
$code = Invoke-AdminEsp 'ipc_ignored_pipe' "--pipe $svc-ignored ipc ping"
Add-Case 'admin_ipc_foreground_ignores_pipe' '1' $code 'ipc' '--pipe is ignored by RunForeground'
$code = Invoke-AdminEsp 'ipc_status' "--pipe $pipe ipc status"
Add-Case 'admin_ipc_status' '0' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_exports' "--pipe $pipe ipc exports"
Add-Case 'admin_ipc_exports' '0' $code 'ipc' ''
$ipcRules = New-UniqueRules (Join-Path $RulesDir 'monitor_process_create.xml')
$code = Invoke-AdminEsp 'ipc_rules' "--pipe $pipe ipc rules --rules $ipcRules"
Add-Case 'admin_ipc_rules' '0' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_rules_missing_file' "--pipe $pipe ipc rules --rules C:\this\does\not\exist.xml"
Add-Case 'admin_ipc_rules_missing_file' '1' $code 'ipc' ''
$code = Invoke-AdminEsp 'ipc_ping_eq' ("--pipe=" + $pipe + ' ipc ping')
Add-Case 'admin_ipc_ping_pipe_eq' '0' $code 'ipc' '--pipe=value'
$code = Invoke-AdminEsp 'ipc_rules_bad' "--pipe $pipe ipc rules --rules $RulesDir\fixture_process_create_process_bad_eventtype.xml"
Add-Case 'admin_ipc_rules_bad' '0' $code 'ipc' 'exchange succeeds; payload is parse error'
Stop-Process -Name esptool -Force -ErrorAction SilentlyContinue
Unregister-ScheduledTask -TaskName ($script:TaskPrefix + 'fg') -Confirm:$false -ErrorAction SilentlyContinue
Start-Sleep -Seconds 1

# SCM start BEFORE protect. ImagePath is `esptool.exe service run --log ...`
# so the dispatcher and pipe use the default name esptool, not --service.
$code = Invoke-AdminEsp 'svc_start' "--service $svc service run"
Add-Case 'admin_service_run_not_scm' '1' $code 'service' 'StartServiceCtrlDispatcher fails outside SCM'
Get-Process -Name esptool -ErrorAction SilentlyContinue | Stop-Process -Force -ErrorAction SilentlyContinue
sc.exe stop esptool | Out-Null
$scmStart = sc.exe start $svc
Write-Output ($scmStart | Out-String)
Start-Sleep -Seconds 4
$scmRunning = $false
try {
    $scmRunning = ((Get-Service -Name $svc -ErrorAction Stop).Status -eq 'Running')
} catch {
    $scmRunning = $false
}
if ($scmRunning) {
    $code = Invoke-AdminEsp 'ipc_scm_ping' 'ipc ping --pipe esptool'
    Add-Case 'admin_ipc_scm_ping' '0' $code 'ipc' 'ImagePath pipe is esptool'
    $code = Invoke-AdminEsp 'ipc_scm_status' 'ipc status --pipe esptool'
    Add-Case 'admin_ipc_scm_status' '0' $code 'ipc' ''
    $code = Invoke-AdminEsp 'ipc_scm_exports' 'ipc exports --pipe esptool'
    Add-Case 'admin_ipc_scm_exports' '0' $code 'ipc' ''
    sc.exe stop $svc | Out-Null
    Start-Sleep -Seconds 1
} else {
    Add-Case 'admin_ipc_scm_ping' '0' -1 'ipc' 'sc start failed'
    Add-Case 'admin_ipc_scm_status' '0' -1 'ipc' 'sc start failed'
    Add-Case 'admin_ipc_scm_exports' '0' -1 'ipc' 'sc start failed'
}

sc.exe stop $svc | Out-Null
sc.exe delete $svc | Out-Null

Stop-SmokeTasks
Stop-Process -Name esptool -Force -ErrorAction SilentlyContinue

}

# ---------------------------------------------------------------------------
# coverage map + summary
# ---------------------------------------------------------------------------
if ($DenyOnly) {
    $coverage = [ordered]@{
        flags  = [ordered]@{}
        events = [ordered]@{}
    }
} else {
$coverage = [ordered]@{
    commands = [ordered]@{
        exports        = @('admin_exports', 'sys_exports')
        status         = @('admin_status', 'sys_status')
        connect        = @('admin_connect_hop', 'sys_connect_noprov', 'sys_connect_restricted', 'sys_connect_full', 'sys_hop_connect_noprov', 'sys_hop_connect_auto', 'sys_hop_connect_permission')
        rules          = @('sys_rules_missing', 'sys_hop_rules', 'sys_rules_equals', 'admin_rules_missing_hop', 'sys_rules_fixture_process_create_process_bad_eventtype', 'sys_rules_fixture_collection_open_missing_guid')
        monitor        = @('admin_monitor_hop', 'monitor_process_create', 'sys_monitor_idle', 'sys_hop_monitor_idle', 'sys_monitor_equals_flags', 'monitor_fo_open_name', 'monitor_fo_create_name', 'monitor_fo_equals_win32', 'monitor_fo_equals_neg', 'monitor_proc_ntpath', 'monitor_reg_create', 'monitor_query_registry', 'monitor_reg_ntpath', 'monitor_reg_querykey', 'monitor_reg_enumkey', 'monitor_thread_start', 'monitor_ob_dup', 'monitor_fs_dir', 'monitor_iocp_process', 'monitor_thread_term', 'monitor_reg_delete', 'monitor_reg_queryvalue', 'monitor_filter_process_create_process_collection', 'monitor_filter_process_create_process_collection_named', 'monitor_filter_process_create_process_collection_integer', 'monitor_filter_process_create_process_collection_binary', 'monitor_query_process', 'monitor_query_event', 'monitor_query_token', 'monitor_query_client', 'monitor_and_process', 'monitor_xor_process', 'monitor_process_ntpath_ne', 'monitor_process_pattern', 'monitor_process_implicit_and', 'monitor_create_trio_named', 'monitor_query_process_token', 'monitor_process_type0', 'monitor_reg_open', 'monitor_reg_setvalue', 'monitor_ktm_commit', 'monitor_query_ktm', 'monitor_ktm_rollback', 'monitor_reg_rename', 'monitor_reg_setsec', 'monitor_reg_load', 'monitor_reg_enumvalue', 'monitor_reg_deletevalue', 'monitor_filter_pipe_create_pipe', 'monitor_query_pipe', 'monitor_filter_mailslot_create_mailslot', 'monitor_query_mailslot', 'monitor_proc_not', 'monitor_proc_ntpath_neg', 'monitor_boot_9000')
        query          = @('admin_query_hop', 'sys_query', 'sys_hop_query', 'sys_query_kind_process', 'sys_query_kind_token', 'sys_query_kind_stream', 'sys_query_kind_event', 'sys_query_kind_event_nosup', 'sys_query_kind_ktm', 'sys_query_kind_client', 'sys_query_kind_client_noprops', 'sys_query_kind_rko')
        refs           = @('admin_refs_hop', 'sys_refs', 'sys_hop_refs', 'sys_refs_missing_kind', 'sys_refs_props', 'sys_refs_duplicate', 'sys_refs_file', 'sys_refs_registry', 'sys_refs_thread', 'sys_refs_desktop', 'sys_refs_process_token', 'sys_refs_thread_token', 'sys_refs_stream', 'sys_refs_from_notify_norules', 'sys_refs_from_notify', 'sys_refs_from_notify_fo')
        collections    = @('admin_collections_hop', 'sys_collections', 'sys_hop_collections', 'sys_collections_type1', 'sys_collections_type2_enum_open', 'sys_collections_type3', 'sys_collections_session')
        context        = @('admin_context_hop', 'sys_context', 'sys_hop_context')
        clients        = @('admin_clients_hop', 'sys_clients', 'sys_hop_clients', 'sys_clients_cleared')
        unregister     = @('admin_unregister_hop', 'sys_unregister_all', 'sys_unregister_before_persist', 'sys_unregister_after_persist', 'sys_unregister_missing_guid', 'sys_unregister_bad_guid', 'sys_unregister_zero_guid', 'sys_unregister_zero_guid_eq')
        'enum-rules'   = @('admin_enum_rules_hop', 'sys_enum_rules', 'sys_hop_enum_rules')
        'remove-rules' = @('admin_remove_rules_hop', 'sys_remove_rules', 'sys_hop_remove_rules')
        'persist-rules'= @('admin_persist_rules_hop', 'sys_persist_rules', 'sys_persist_rules_missing', 'sys_hop_persist_rules')
        'open-queue'   = @('admin_open_queue_hop', 'sys_open_queue', 'sys_hop_open_queue')
        trust          = @('admin_trust_hop', 'sys_trust', 'sys_hop_trust', 'sys_trust_abcd')
        exercise       = @('admin_exercise_hop', 'sys_exercise', 'sys_exercise_isolated')
        'call-one'     = @('sys_call_one_missing', 'sys_call_one_unknown')
        'ppl status'   = @('admin_ppl_status')
        'token status' = @('admin_token_status')
        'token set'    = @('admin_token_set_denied', 'sys_token_set_restricted', 'sys_token_set_full', 'sys_token_set_default', 'sys_token_set_permission_eq', 'sys_token_set_permission_space', 'sys_token_set_permission_full_eq', 'sys_token_bad_perm')
        'token clear'  = @('admin_token_clear_denied', 'sys_token_clear_fresh')
        provision      = @('admin_provision_hop', 'sys_provision_noprov_fresh', 'sys_provision_after_set', 'sys_hop_provision')
        'service install' = @('admin_service_install', 'admin_service_imagepath_noprov', 'admin_service_reinstall', 'admin_service_install_dup', 'admin_service_equals_name', 'admin_service_install_provision', 'admin_service_imagepath_provision')
        'service uninstall' = @('sys_service_uninstall_clean')
        'service run'  = @('admin_service_run_not_scm', 'admin_ipc_scm_ping')
        'service foreground' = @('admin_ipc_ping', 'admin_ipc_foreground_ignores_pipe')
        'ipc ping'     = @('admin_ipc_ping_noserver', 'admin_ipc_ping', 'admin_ipc_ping_pipe_eq', 'admin_ipc_scm_ping')
        'ipc status'   = @('admin_ipc_status_noserver', 'admin_ipc_status', 'admin_ipc_scm_status')
        'ipc exports'  = @('admin_ipc_exports_noserver', 'admin_ipc_exports', 'admin_ipc_scm_exports')
        'ipc exercise' = @('admin_ipc_exercise_noserver')
        'ipc rules'    = @('admin_ipc_rules_nopath', 'admin_ipc_rules', 'admin_ipc_rules_missing_file', 'admin_ipc_rules_bad')
    }
    options = [ordered]@{
        '--help'         = @('cli_help')
        '-h'             = @('cli_help_h')
        '--dll'          = @('admin_exports', 'cli_missing_dll', 'cli_dll_missing_file')
        '--dll=value'    = @('cli_exports_equals_dll')
        '--rules'        = @('sys_rules_missing', 'cli_missing_rules')
        '--rules=value'  = @('sys_rules_equals')
        '--log'          = @('cli_status_level_TRACE', 'cli_missing_log', 'cli_status_log_eq')
        '--log=value'    = @('cli_status_log_eq')
        '--pipe'         = @('admin_ipc_ping', 'cli_missing_pipe', 'admin_ipc_foreground_ignores_pipe')
        '--pipe=value'   = @('admin_ipc_ping_pipe_eq')
        '--service'      = @('admin_service_install', 'cli_missing_service')
        '--service=value' = @('admin_service_equals_name')
        '--level'        = @('cli_status_level_TRACE', 'cli_status_level_unknown', 'cli_missing_level', 'cli_status_level_eq')
        '--level=value'  = @('cli_status_level_eq')
        '--target'       = @('cli_status_level_TRACE', 'cli_missing_target', 'cli_status_target_eq')
        '--target=value' = @('cli_status_target_eq')
        '--duration'     = @('cli_missing_duration', 'cli_invalid_duration')
        '--duration=ms'  = @('sys_monitor_equals_flags')
        '--max'          = @('cli_missing_max', 'cli_invalid_max')
        '--max=count'    = @('sys_monitor_equals_flags')
        '--isolated'     = @('sys_exercise_isolated')
        '--json'         = @('cli_status_level_TRACE')
        '--permission'   = @('sys_connect_restricted', 'sys_connect_full', 'cli_missing_permission', 'sys_token_set_permission_eq', 'sys_token_set_permission_space')
        '--no-provision' = @('sys_connect_noprov', 'admin_service_imagepath_provision', 'cli_conflict_prov_force', 'cli_conflict_prov_perm')
        '--no-auto-provision' = @('cli_help')
        '--force-provision' = @('cli_conflict_prov_force')
        '--force-hop'    = @('cli_conflict_hop')
        '--no-hop'       = @('cli_conflict_hop')
        '--worker'       = @('sys_connect_noprov')
        '--verbose'      = @('cli_status_level_TRACE')
        '-v'             = @('cli_status_level_TRACE')
        '--helpfulness'  = @('cli_helpfulness')
        '--iocp'         = @('monitor_iocp_process')
        '--guid'         = @('cli_missing_guid', 'sys_unregister_missing_guid', 'sys_unregister_bad_guid', 'sys_unregister_zero_guid')
        '--guid=value'   = @('sys_unregister_zero_guid_eq')
        '--all'          = @('sys_unregister_all', 'sys_unregister_before_persist', 'sys_unregister_after_persist')
        '--kind'         = @('cli_missing_kind', 'sys_query_kind_process', 'sys_query_kind_event')
        '--pid'          = @('cli_missing_pid', 'sys_refs', 'sys_refs_props')
        '--tid'          = @('cli_missing_tid', 'sys_refs_thread', 'sys_refs_thread_token')
        '--path'         = @('cli_missing_path', 'sys_refs_file', 'sys_refs_registry')
        '--file-id'      = @('cli_missing_file_id')
        '--volume'       = @('cli_missing_volume')
        '--stream'       = @('cli_missing_stream', 'sys_refs_stream')
        '--name'         = @('cli_missing_name', 'sys_refs_desktop')
        '--event-id'     = @('cli_missing_event_id')
        '--properties'   = @('cli_missing_properties', 'sys_refs_props', 'sys_query_kind_process')
        '--supported'    = @('cli_missing_supported', 'sys_refs_props', 'sys_query_kind_event')
        '--from-notify'  = @('sys_refs_from_notify', 'sys_refs_from_notify_fo', 'sys_refs_from_notify_norules')
        '--duplicate'    = @('sys_refs_duplicate')
        '--context-enum' = @('sys_refs_duplicate')
        '--type'         = @('cli_missing_type', 'cli_invalid_type', 'sys_collections_type1', 'sys_collections_type2_enum_open', 'sys_collections_type3')
        '--lifetime'     = @('cli_missing_lifetime', 'cli_invalid_lifetime', 'sys_collections_type2_enum_open')
        '--enum-ids'     = @('sys_collections_type2_enum_open')
        '--open'         = @('sys_collections_type2_enum_open')
        '--'             = @('cli_dashdash')
    }
    events = [ordered]@{
        '2'    = @('monitor_thread_start')
        '3'    = @('monitor_thread_term')
        '1000' = @('monitor_process_create', 'monitor_proc_ntpath', 'monitor_iocp_process', 'monitor_query_process', 'monitor_query_event', 'monitor_query_token', 'monitor_query_client', 'monitor_and_process', 'monitor_xor_process', 'monitor_process_ntpath_ne', 'monitor_process_pattern', 'monitor_process_implicit_and', 'monitor_create_trio_named', 'monitor_query_process_token', 'monitor_process_type0')
        '2000' = @('monitor_fo_create_name', 'monitor_fo_equals_win32', 'monitor_create_trio_named')
        '2001' = @('monitor_fo_open_name')
        '3004' = @('monitor_fs_dir')
        '3010' = @('monitor_ktm_commit', 'monitor_query_ktm')
        '3011' = @('monitor_ktm_rollback')
        '5000' = @('monitor_filter_pipe_create_pipe', 'monitor_query_pipe')
        '6000' = @('monitor_filter_mailslot_create_mailslot', 'monitor_query_mailslot')
        '7000' = @('monitor_reg_create', 'monitor_query_registry', 'monitor_reg_ntpath')
        '7001' = @('monitor_reg_open')
        '7002' = @('monitor_reg_delete')
        '7003' = @('monitor_reg_setvalue')
        '7004' = @('monitor_reg_deletevalue')
        '7005' = @('monitor_reg_rename')
        '7008' = @('monitor_reg_setsec')
        '7009' = @('monitor_reg_querykey')
        '7010' = @('monitor_reg_queryvalue')
        '7012' = @('monitor_reg_load')
        '7013' = @('monitor_reg_enumkey')
        '7014' = @('monitor_reg_enumvalue')
        '8001' = @('monitor_ob_dup')
        '9000' = @('monitor_boot_9000')
    }
}
if (-not $SkipHeavy) {
    $coverage.events['4000'] = @('monitor_vol_mount')
    $coverage.events['4001'] = @('monitor_vol_dismount')
}

$caseNames = @($script:Cases | ForEach-Object { $_.name })
$missingEvents = @()
foreach ($eventId in $coverage.events.Keys) {
    $mapped = @($coverage.events[$eventId])
    $hit = $false
    foreach ($name in $mapped) {
        if ($caseNames -contains $name) { $hit = $true; break }
    }
    if (-not $hit) { $missingEvents += [string]$eventId }
}
if ($missingEvents.Count -gt 0) {
    Add-Case 'event_id_coverage' '0' 1 'coverage' ('missing=' + ($missingEvents -join ','))
} else {
    Add-Case 'event_id_coverage' '0' 0 'coverage' ('ids=' + $coverage.events.Count)
}

$heavyLeaves = @(
    'filter_vol_fsctl_disk.xml',
    'filter_vol_fsctl_volume.xml',
    'monitor_vol_dismount.xml',
    'monitor_vol_fsctl_query_disk.xml',
    'monitor_vol_fsctl_query_volume.xml',
    'monitor_vol_mount.xml',
    'monitor_volume_set.xml'
)
$missingLeaves = @()
Get-ChildItem -LiteralPath $RulesDir -Filter '*.xml' | ForEach-Object {
    if ($script:SkipHeavy -and ($heavyLeaves -contains $_.Name)) { return }
    if (-not $script:RulesUsed.Contains($_.Name)) { $missingLeaves += $_.Name }
}
if ($missingLeaves.Count -gt 0) {
    Add-Case 'xml_leaf_coverage' '0' 1 'coverage' ('missing=' + ($missingLeaves -join ','))
} else {
    Add-Case 'xml_leaf_coverage' '0' 0 'coverage' ('leaves=' + $script:RulesUsed.Count)
}
}

# Materialize the case list before it is wrapped. A generic List[object] cannot
# be converted with @(...) on PowerShell 7.6.x: the array-subexpression path
# throws ArgumentException "Argument types do not match", which terminates the
# statement, leaves the summary unassigned, and makes ConvertTo-Json write the
# literal null. ToArray() takes the working conversion path.
$caseArray = $script:Cases.ToArray()
$pass = @($caseArray | Where-Object { $_.verdict -eq 'PASS' }).Count
$fail = @($caseArray | Where-Object { $_.verdict -eq 'FAIL' }).Count
try {
    $summary = [ordered]@{
        exe        = $Exe
        dll        = $Dll
        rules_dir  = $RulesDir
        out_dir    = $OutDir
        case_count = $caseArray.Length
        pass       = $pass
        fail       = $fail
        cases      = $caseArray
    }
    $json = $summary | ConvertTo-Json -Depth 6
    if ([string]::IsNullOrWhiteSpace($json) -or $json -eq 'null') {
        throw 'summary serialized to null'
    }
    Set-Content -LiteralPath $script:SummaryJson -Value $json -Encoding UTF8
} catch {
    $compact = [ordered]@{
        exe        = $Exe
        dll        = $Dll
        rules_dir  = $RulesDir
        out_dir    = $OutDir
        case_count = $caseArray.Length
        pass       = $pass
        fail       = $fail
        json_error = [string]$_.Exception.Message
    }
    $compact | ConvertTo-Json -Depth 4 | Set-Content -LiteralPath $script:SummaryJson -Encoding UTF8
    Write-Output ('summary json fallback: ' + $_.Exception.Message)
}
try {
    $coverage | ConvertTo-Json -Depth 6 | Set-Content -LiteralPath $script:CoverageJson -Encoding UTF8
} catch {
    Write-Output ('coverage json failed: ' + $_.Exception.Message)
}

Write-Output '===== SUMMARY ====='
Get-Content -LiteralPath $script:SummaryTsv
Write-Output ("PASS={0} FAIL={1} TOTAL={2}" -f $pass, $fail, $script:Cases.Count)
Write-Output ("summary={0}" -f $script:SummaryTsv)
Write-Output ("json={0}" -f $script:SummaryJson)
if ($fail -gt 0) { exit 1 }
exit 0
