# Starts and joins a thread, then opens a process handle.
$ErrorActionPreference = 'Continue'
$thread = [System.Threading.Thread]::new([System.Threading.ThreadStart]{ Start-Sleep -Milliseconds 50 })
$thread.Start()
$thread.Join()
[void](Get-Process -Id $PID).Handle
Write-Output 'thread-handle trigger done'
