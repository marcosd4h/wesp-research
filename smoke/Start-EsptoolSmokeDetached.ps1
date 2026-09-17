# Guest-side detached start. Lives next to Run-EsptoolSmoke.ps1 and
# esptool.exe. Prefers rules\ next to this script (pushed guest
# payload). Falls back to ..\rules for an in-repo run against
# tools/esptool/rules.
param(
    [string]$OutName = 'results',
    [switch]$DenyOnly,
    [switch]$SkipIsolated,
    [switch]$SkipHeavy
)

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
$runner = Join-Path $root 'Run-EsptoolSmoke.ps1'
$tool = Join-Path $root 'esptool.exe'
$out = Join-Path $root $OutName
$rules = Join-Path $root 'rules'
$localXml = @(Get-ChildItem -LiteralPath $rules -Filter '*.xml' -ErrorAction SilentlyContinue)
if ($localXml.Count -lt 1) {
    $rules = Join-Path (Split-Path -Parent $root) 'rules'
}

if (-not (Test-Path -LiteralPath $runner)) { Write-Output 'runner-missing'; exit 2 }
if (-not (Test-Path -LiteralPath $tool)) { Write-Output 'exe-missing'; exit 2 }
$xml = @(Get-ChildItem -LiteralPath $rules -Filter '*.xml' -ErrorAction SilentlyContinue)
if ($xml.Count -lt 1) { Write-Output 'rules-missing'; exit 2 }

Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*Run-EsptoolSmoke.ps1*' } |
    ForEach-Object { try { Stop-Process -Id $_.ProcessId -Force -ErrorAction Stop } catch {} }

if (Test-Path -LiteralPath $out) {
    Remove-Item -LiteralPath $out -Recurse -Force -ErrorAction SilentlyContinue
}
New-Item -ItemType Directory -Force -Path $out | Out-Null

$flags = ''
if ($DenyOnly) { $flags += ' -DenyOnly' }
if ($SkipIsolated) { $flags += ' -SkipIsolated' }
if ($SkipHeavy) { $flags += ' -SkipHeavy' }

$pwsh = 'C:\Windows\System32\WindowsPowerShell\v1.0\powershell.exe'
if (Test-Path -LiteralPath 'C:\Program Files\PowerShell\7\pwsh.exe') {
    $pwsh = 'C:\Program Files\PowerShell\7\pwsh.exe'
}
$arg = '-NoProfile -ExecutionPolicy Bypass -File "{0}" -Exe "{1}" -RulesDir "{2}" -OutDir "{3}"{4}' -f $runner, $tool, $rules, $out, $flags
$line = '"{0}" {1}' -f $pwsh, $arg
$r = Invoke-CimMethod -ClassName Win32_Process -MethodName Create -Arguments @{
    CommandLine      = $line
    CurrentDirectory = $root
}
$code = [int]$r.ReturnValue
$procId = [int]$r.ProcessId
Start-Sleep -Seconds 4
$alive = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*Run-EsptoolSmoke.ps1*' }).Count
Write-Output ("wmi_return={0} pid={1} smoke_alive={2} out={3}" -f $code, $procId, $alive, $out)
if ($code -ne 0 -or $procId -le 0) { exit 1 }
if ($alive -lt 1) { exit 1 }
exit 0
