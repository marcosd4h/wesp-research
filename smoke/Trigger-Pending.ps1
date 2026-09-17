# Guest triggers used by the gap live cases. Each mode is a separate
# powershell.exe process started from a SYSTEM scheduled-task wrapper.
param(
    [Parameter(Mandatory = $true)][string]$Mode,
    [string]$WorkDir,
    [string]$ObjectName = 'esptool_gap'
)
$ErrorActionPreference = 'Continue'
if (-not $WorkDir) {
    $WorkDir = Join-Path $PSScriptRoot 'pending-work'
}
New-Item -ItemType Directory -Force -Path $WorkDir | Out-Null

switch ($Mode) {
    'ktm' {
        $src = @'
using System;
using System.Runtime.InteropServices;
using System.Text;
public static class EspTxf {
  [DllImport("ktmw32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateTransaction(IntPtr a, IntPtr u, uint o, uint i, uint t, uint ms, string d);
  [DllImport("ktmw32.dll", SetLastError=true)] public static extern bool CommitTransaction(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileTransactedW(string p, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t, IntPtr tx, IntPtr mini, IntPtr ext);
  [DllImport("kernel32.dll", SetLastError=true)] public static extern bool WriteFile(IntPtr h, byte[] b, int n, out int w, IntPtr o);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string path) {
    IntPtr tx = CreateTransaction(IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, "esptool-smoke-txf");
    if (tx == IntPtr.Zero || tx == new IntPtr(-1)) return 2;
    IntPtr h = CreateFileTransactedW(path, 0x40000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero, tx, IntPtr.Zero, IntPtr.Zero);
    if (h == new IntPtr(-1)) { CloseHandle(tx); return 3; }
    byte[] data = Encoding.ASCII.GetBytes("txf");
    int wrote;
    WriteFile(h, data, data.Length, out wrote, IntPtr.Zero);
    CloseHandle(h);
    bool ok = CommitTransaction(tx);
    CloseHandle(tx);
    return ok ? 0 : 1;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspTxf]::Run((Join-Path $WorkDir 'txf.txt'))
    }
    'volmount' {
        $vhd = Join-Path $WorkDir 'pend.vhdx'
        $script = Join-Path $WorkDir 'pend_diskpart.txt'
        if (Test-Path -LiteralPath $vhd) {
            $detach = @("select vdisk file=$vhd", 'detach vdisk') -join "`r`n"
            Set-Content -LiteralPath $script -Value $detach -Encoding ASCII
            diskpart /s $script | Out-Null
            Remove-Item -LiteralPath $vhd -Force -ErrorAction SilentlyContinue
        }
        $body = @(
            "create vdisk file=$vhd maximum=8 type=expandable"
            "select vdisk file=$vhd"
            'attach vdisk'
            'create partition primary'
            'format fs=ntfs quick label=ESPEND'
            'assign'
        ) -join "`r`n"
        Set-Content -LiteralPath $script -Value $body -Encoding ASCII
        diskpart /s $script
    }
    'regrename' {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspRename {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int RegOpenKeyExW(UIntPtr h, string sub, uint opt, uint sam, out IntPtr key);
  [DllImport("ntdll.dll")] public static extern int NtRenameKey(IntPtr key, ref UNICODE_STRING name);
  [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr key);
  [StructLayout(LayoutKind.Sequential)]
  public struct UNICODE_STRING { public ushort Length; public ushort MaximumLength; public IntPtr Buffer; }
  public static int Run() {
    IntPtr key;
    int st = RegOpenKeyExW(new UIntPtr(0x80000001u), "Software\\esptool_pend_ren", 0, 0xF003F, out key);
    if (st != 0) return st;
    string n = "esptool_pend_ren2";
    var us = new UNICODE_STRING();
    us.Buffer = Marshal.StringToHGlobalUni(n);
    us.Length = (ushort)(n.Length * 2);
    us.MaximumLength = (ushort)(us.Length + 2);
    st = NtRenameKey(key, ref us);
    Marshal.FreeHGlobal(us.Buffer);
    RegCloseKey(key);
    return st;
  }
}
'@
        reg.exe add HKCU\Software\esptool_pend_ren /f | Out-Null
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspRename]::Run()
        reg.exe delete HKCU\Software\esptool_pend_ren2 /f | Out-Null
        reg.exe delete HKCU\Software\esptool_pend_ren /f | Out-Null
    }
    'regsetsec' {
        $src = @'
using System;
using System.Security.AccessControl;
using Microsoft.Win32;
public static class EspSetSec {
  public static int Run() {
    using (var key = Registry.CurrentUser.CreateSubKey("Software\\esptool_pend_sec", true)) {
      var acl = key.GetAccessControl();
      acl.AddAccessRule(new RegistryAccessRule("Everyone", RegistryRights.ReadKey, AccessControlType.Allow));
      key.SetAccessControl(acl);
    }
    Registry.CurrentUser.DeleteSubKey("Software\\esptool_pend_sec", false);
    return 0;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspSetSec]::Run()
    }
    'ktmrollback' {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspTxfRb {
  [DllImport("ktmw32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateTransaction(IntPtr a, IntPtr u, uint o, uint i, uint t, uint ms, string d);
  [DllImport("ktmw32.dll", SetLastError=true)] public static extern bool RollbackTransaction(IntPtr h);
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateFileTransactedW(string p, uint a, uint s, IntPtr sec, uint d, uint f, IntPtr t, IntPtr tx, IntPtr mini, IntPtr ext);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string path) {
    IntPtr tx = CreateTransaction(IntPtr.Zero, IntPtr.Zero, 0, 0, 0, 0, "esptool-smoke-txf-rb");
    if (tx == IntPtr.Zero || tx == new IntPtr(-1)) return 2;
    IntPtr h = CreateFileTransactedW(path, 0x40000000, 0, IntPtr.Zero, 2, 0x80, IntPtr.Zero, tx, IntPtr.Zero, IntPtr.Zero);
    if (h == new IntPtr(-1)) { CloseHandle(tx); return 3; }
    CloseHandle(h);
    bool ok = RollbackTransaction(tx);
    CloseHandle(tx);
    return ok ? 0 : 1;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspTxfRb]::Run((Join-Path $WorkDir 'txf_rb.txt'))
    }
    'voldismount' {
        $vhd = Join-Path $WorkDir 'pend_dismount.vhdx'
        $script = Join-Path $WorkDir 'pend_dismount.txt'
        if (Test-Path -LiteralPath $vhd) {
            Set-Content -LiteralPath $script -Value ("select vdisk file=$vhd`r`ndetach vdisk") -Encoding ASCII
            diskpart /s $script | Out-Null
            Remove-Item -LiteralPath $vhd -Force -ErrorAction SilentlyContinue
        }
        $body = @(
            "create vdisk file=$vhd maximum=8 type=expandable"
            "select vdisk file=$vhd"
            'attach vdisk'
            'detach vdisk'
        ) -join "`r`n"
        Set-Content -LiteralPath $script -Value $body -Encoding ASCII
        diskpart /s $script
    }
    'regreplace' {
        $newHive = Join-Path $WorkDir 'pend_replace_new.hiv'
        $oldHive = Join-Path $WorkDir 'pend_replace_old.hiv'
        reg.exe add HKCU\Software\esptool_pend_rep /f | Out-Null
        reg.exe save HKCU\Software\esptool_pend_rep $newHive /y | Out-Null
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspReplace {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int RegOpenKeyExW(UIntPtr h, string sub, uint opt, uint sam, out IntPtr key);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int RegReplaceKeyW(IntPtr key, string sub, string n, string o);
  [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr key);
  public static int Run(string n, string o) {
    IntPtr key;
    int st = RegOpenKeyExW(new UIntPtr(0x80000001u), "Software\\esptool_pend_rep", 0, 0xF003F, out key);
    if (st != 0) return st;
    st = RegReplaceKeyW(key, null, n, o);
    RegCloseKey(key);
    return st;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspReplace]::Run($newHive, $oldHive)
        reg.exe delete HKCU\Software\esptool_pend_rep /f | Out-Null
    }
    'regrestore' {
        $hive = Join-Path $WorkDir 'pend_restore.hiv'
        reg.exe add HKCU\Software\esptool_pend_rst /f | Out-Null
        reg.exe save HKCU\Software\esptool_pend_rst $hive /y | Out-Null
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspRestore {
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int RegOpenKeyExW(UIntPtr h, string sub, uint opt, uint sam, out IntPtr key);
  [DllImport("advapi32.dll", CharSet=CharSet.Unicode)]
  public static extern int RegRestoreKeyW(IntPtr key, string file, uint flags);
  [DllImport("advapi32.dll")] public static extern int RegCloseKey(IntPtr key);
  public static int Run(string file) {
    IntPtr key;
    int st = RegOpenKeyExW(new UIntPtr(0x80000001u), "Software\\esptool_pend_rst", 0, 0xF003F, out key);
    if (st != 0) return st;
    st = RegRestoreKeyW(key, file, 8);
    RegCloseKey(key);
    return st;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspRestore]::Run($hive)
        reg.exe delete HKCU\Software\esptool_pend_rst /f | Out-Null
    }
    'regload' {
        $hive = Join-Path $WorkDir 'pend.hiv'
        reg.exe add HKCU\Software\esptool_pend_hive /f | Out-Null
        reg.exe save HKCU\Software\esptool_pend_hive $hive /y | Out-Null
        reg.exe load HKU\esptool_pend $hive
        reg.exe unload HKU\esptool_pend
        reg.exe delete HKCU\Software\esptool_pend_hive /f | Out-Null
    }
    'pipe' {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspPipe {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateNamedPipeW(string n, uint om, uint pm, uint inst, uint outb, uint inb, uint to, IntPtr sec);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string name) {
    IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, 3, 0, 1, 256, 256, 0, IntPtr.Zero);
    if (h == new IntPtr(-1)) return 2;
    CloseHandle(h);
    return 0;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspPipe]::Run($ObjectName)
    }
    'mailslot' {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspMail {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateMailslotW(string n, uint max, uint to, IntPtr sec);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string name) {
    IntPtr h = CreateMailslotW("\\\\.\\mailslot\\" + name, 0, 0xFFFFFFFF, IntPtr.Zero);
    if (h == new IntPtr(-1)) return 2;
    CloseHandle(h);
    return 0;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        [EspMail]::Run($ObjectName)
    }
    'pipemail' {
        $src = @'
using System;
using System.Runtime.InteropServices;
public static class EspPipe {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateNamedPipeW(string n, uint om, uint pm, uint inst, uint outb, uint inb, uint to, IntPtr sec);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string name) {
    IntPtr h = CreateNamedPipeW("\\\\.\\pipe\\" + name, 3, 0, 1, 256, 256, 0, IntPtr.Zero);
    if (h == new IntPtr(-1)) return 2;
    CloseHandle(h);
    return 0;
  }
}
public static class EspMail {
  [DllImport("kernel32.dll", SetLastError=true, CharSet=CharSet.Unicode)]
  public static extern IntPtr CreateMailslotW(string n, uint max, uint to, IntPtr sec);
  [DllImport("kernel32.dll")] public static extern bool CloseHandle(IntPtr h);
  public static int Run(string name) {
    IntPtr h = CreateMailslotW("\\\\.\\mailslot\\" + name, 0, 0xFFFFFFFF, IntPtr.Zero);
    if (h == new IntPtr(-1)) return 2;
    CloseHandle(h);
    return 0;
  }
}
'@
        Add-Type -TypeDefinition $src -ErrorAction SilentlyContinue
        $pipeCode = [EspPipe]::Run($ObjectName)
        $mailCode = [EspMail]::Run($ObjectName)
        if ($pipeCode -ne 0) { exit $pipeCode }
        if ($mailCode -ne 0) { exit $mailCode }
    }
    default { Write-Output ("unknown {0}" -f $Mode); exit 2 }
}
exit 0
