# Locks and unlocks one byte so FsLock / FsUnlock can fire.
$ErrorActionPreference = 'Continue'
$path = Join-Path $env:TEMP 'esptool-smoke-lock.bin'
[IO.File]::WriteAllText($path, 'lock')
$f = [IO.File]::Open($path, 'OpenOrCreate', 'ReadWrite', 'None')
$f.Lock(0, 1)
$f.Unlock(0, 1)
$f.Dispose()
Write-Output 'file-lock trigger done'
