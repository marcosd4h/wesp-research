# Spawn a process image and write a structured operation line.
# Denied CreateProcess surfaces as Exception.HResult (live 0x80004005).
param(
    [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output 'operation=MISSING'
    exit 0
}
try {
    $p = New-Object System.Diagnostics.Process
    $p.StartInfo.FileName = $Path
    $p.StartInfo.Arguments = '/c exit 0'
    $p.StartInfo.UseShellExecute = $false
    $p.StartInfo.CreateNoWindow = $true
    [void]$p.Start()
    Write-Output ('operation=OK pid={0}' -f $p.Id)
    try { if (-not $p.HasExited) { $p.Kill() } } catch {}
} catch {
    $hr = [int]$_.Exception.HResult
    Write-Output ('operation=DENIED 0x{0:X8}' -f $hr)
}
exit 0
