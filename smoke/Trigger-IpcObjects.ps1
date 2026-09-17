# Creates a named pipe and a mailslot so PipeCreate / MailslotCreate can fire.
$ErrorActionPreference = 'Continue'
$pipe = [System.IO.Pipes.NamedPipeServerStream]::new(
    'esptool-smoke-pipe',
    [System.IO.Pipes.PipeDirection]::InOut,
    1)
$pipe.Dispose()

Add-Type -TypeDefinition @'
using System;
using System.Runtime.InteropServices;
public static class SmokeMailslot {
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    public static extern IntPtr CreateMailslot(string name, uint maxMessageSize,
        uint readTimeout, IntPtr securityAttributes);
    [DllImport("kernel32.dll", SetLastError = true)]
    public static extern bool CloseHandle(IntPtr handle);
}
'@
$handle = [SmokeMailslot]::CreateMailslot(
    '\\.\mailslot\esptool-smoke-mslot', 0, [uint32]::MaxValue, [IntPtr]::Zero)
if ($handle -ne [IntPtr]::Zero -and $handle.ToInt64() -ne -1) {
    [void][SmokeMailslot]::CloseHandle($handle)
}
Write-Output 'ipc-object trigger done'
