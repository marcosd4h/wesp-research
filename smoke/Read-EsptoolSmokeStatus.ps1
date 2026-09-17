# Guest-side status. Reads summary.tsv next to this script.
param([string]$OutName = 'results')

$ErrorActionPreference = 'Continue'
$root = $PSScriptRoot
if (-not $root) { $root = (Get-Location).Path }
$out = Join-Path $root $OutName
$log = Join-Path $out 'smoke_run.log'
$tsv = Join-Path $out 'summary.tsv'
$alive = @(Get-CimInstance Win32_Process -ErrorAction SilentlyContinue |
    Where-Object { $_.CommandLine -like '*Run-EsptoolSmoke.ps1*' }).Count
Write-Output ('smoke_alive=' + $alive)
if (Test-Path -LiteralPath $tsv) {
    $rows = @(Get-Content -LiteralPath $tsv | Select-Object -Skip 1)
    $pass = @($rows | Where-Object { $_ -match '\tPASS\t' }).Count
    $fail = @($rows | Where-Object { $_ -match '\tFAIL\t' }).Count
    Write-Output ('tsv_rows=' + $rows.Count + ' pass=' + $pass + ' fail=' + $fail)
    Write-Output '=== last 12 tsv ==='
    $rows | Select-Object -Last 12
    Write-Output '=== fails ==='
    $fails = @($rows | Where-Object { $_ -match '\tFAIL\t' })
    if ($fails.Count -eq 0) { Write-Output '(none)' } else { $fails | Select-Object -First 50 }
} else {
    Write-Output 'summary.tsv missing'
}
if (Test-Path -LiteralPath $log) {
    Write-Output ('log_bytes=' + (Get-Item -LiteralPath $log).Length)
    Write-Output '=== log tail ==='
    Get-Content -LiteralPath $log -Tail 10
}
exit 0
