# CreateFileW CREATE_NEW so FoCreate property-1 equals can see a new file.
param(
    [Parameter(Mandatory = $true)][string]$Path
)
$ErrorActionPreference = 'Continue'
$parent = Split-Path -Parent $Path
if ($parent) {
    New-Item -ItemType Directory -Force -Path $parent | Out-Null
}
Remove-Item -LiteralPath $Path -Force -ErrorAction SilentlyContinue
$src = @'
using System;
using System.Runtime.InteropServices;
public static class EspCreateNew {
  [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
  public static extern IntPtr CreateFileW(string p, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string path) {
    IntPtr h = CreateFileW(path, 0x40000000, 0, IntPtr.Zero, 1, 0x80, IntPtr.Zero);
    if (h == new IntPtr(-1)) return Marshal.GetLastWin32Error();
    CloseHandle(h);
    return 0;
  }
}
'@
Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
$code = [EspCreateNew]::Run($Path)
Write-Output ("create={0} exists={1}" -f $code, (Test-Path -LiteralPath $Path))
exit 0
