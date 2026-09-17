# Maps a file so FsCreateSection can fire.
$ErrorActionPreference = 'Continue'
$path = Join-Path $env:TEMP 'esptool-smoke-section.bin'
if ($args.Count -ge 1 -and $args[0]) { $path = [string]$args[0] }
[IO.File]::WriteAllText($path, 'section')
$map = [IO.MemoryMappedFiles.MemoryMappedFile]::CreateFromFile(
    $path, [IO.FileMode]::Open, 'esptoolgap')
$map.Dispose()
Write-Output 'section trigger done'
