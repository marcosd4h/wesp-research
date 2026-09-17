# Open an existing file and write a structured operation line.
# Denied File.Open surfaces as Exception.HResult (live 0x80070490).
param(
    [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Continue'
if (-not (Test-Path -LiteralPath $Path)) {
    Write-Output 'operation=MISSING'
    exit 0
}
try {
    $fs = [System.IO.File]::Open(
        $Path,
        [System.IO.FileMode]::Open,
        [System.IO.FileAccess]::Read,
        [System.IO.FileShare]::Read
    )
    $fs.Dispose()
    Write-Output 'operation=OK'
} catch {
    $hr = [int]$_.Exception.HResult
    Write-Output ('operation=DENIED 0x{0:X8}' -f $hr)
}
exit 0
