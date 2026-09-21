param(
    [Parameter(Mandatory=$true)][ValidateSet('read','create')][string]$Operation,
    [Parameter(Mandatory=$true)][string]$KeyPath
)
$ErrorActionPreference = 'Stop'
# Fixed native file operations only. Paths and key bytes are data, never code.
Add-Type -TypeDefinition @'
using System;
using System.IO;
using System.Runtime.InteropServices;
using System.Security.AccessControl;
using System.Security.Principal;
using Microsoft.Win32.SafeHandles;
public static class Shadow6KeyFile {
    [StructLayout(LayoutKind.Sequential)]
    struct Info {
        public uint Attributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME Creation, Access, Write;
        public uint Volume, SizeHigh, SizeLow, Links, IndexHigh, IndexLow;
    }
    [DllImport("kernel32.dll", CharSet=CharSet.Unicode, SetLastError=true)]
    static extern SafeFileHandle CreateFile(string path, uint access, uint share,
        IntPtr security, uint disposition, uint flags, IntPtr template);
    [DllImport("kernel32.dll", SetLastError=true)]
    static extern bool GetFileInformationByHandle(SafeFileHandle file, out Info info);
    [DllImport("advapi32.dll", SetLastError=true)]
    static extern uint GetSecurityInfo(SafeFileHandle handle, uint type, uint flags,
        out IntPtr owner, out IntPtr group, out IntPtr dacl, out IntPtr sacl, out IntPtr descriptor);
    [DllImport("advapi32.dll")]
    static extern uint GetSecurityDescriptorLength(IntPtr descriptor);
    [DllImport("kernel32.dll")]
    static extern IntPtr LocalFree(IntPtr memory);
    static void Verify(SafeFileHandle handle) {
        Info info;
        if (!GetFileInformationByHandle(handle, out info) ||
            (info.Attributes & (0x400u | 0x10u)) != 0 || info.SizeHigh != 0 ||
            info.SizeLow != 32 || info.Links != 1) throw new IOException("invalid key file");
        IntPtr owner, group, dacl, sacl, descriptor;
        if (GetSecurityInfo(handle, 1, 5, out owner, out group, out dacl, out sacl, out descriptor) != 0)
            throw new IOException("cannot inspect key security");
        try {
            uint length = GetSecurityDescriptorLength(descriptor);
            if (length == 0 || length > 65536) throw new IOException("invalid key security size");
            byte[] raw = new byte[length]; Marshal.Copy(descriptor, raw, 0, raw.Length);
            var security = new RawSecurityDescriptor(raw, 0);
            var user = WindowsIdentity.GetCurrent().User;
            if (!user.Equals(security.Owner) || security.DiscretionaryAcl == null)
                throw new UnauthorizedAccessException("key must be owned by current user with a DACL");
            foreach (GenericAce entry in security.DiscretionaryAcl) {
                var ace = entry as CommonAce;
                if (ace == null || ace.IsCallback) throw new UnauthorizedAccessException("unsupported key ACE");
                if ((ace.AceFlags & AceFlags.InheritOnly) == 0 &&
                    ace.AceQualifier == AceQualifier.AccessAllowed && !user.Equals(ace.SecurityIdentifier))
                    throw new UnauthorizedAccessException("key grants another principal access");
            }
        } finally { LocalFree(descriptor); }
    }
    public static byte[] Read(string path) {
        // No write/delete sharing; do not follow a final reparse point.
        using (var handle = CreateFile(path, 0x80020000u, 1, IntPtr.Zero, 3, 0x00200000u, IntPtr.Zero)) {
            if (handle.IsInvalid) throw new IOException("cannot open key file");
            Verify(handle);
            using (var stream = new FileStream(handle, FileAccess.Read)) {
                byte[] bytes = new byte[32]; int count = 0;
                while (count < bytes.Length) {
                    int n = stream.Read(bytes, count, bytes.Length-count);
                    if (n == 0) throw new IOException("truncated key"); count += n;
                }
                if (stream.ReadByte() != -1) throw new IOException("oversized key");
                Verify(handle); return bytes;
            }
        }
    }
    public static void Create(string path, byte[] bytes) {
        if (bytes.Length != 32) throw new IOException("key must be 32 bytes");
        var user = WindowsIdentity.GetCurrent().User;
        var security = new FileSecurity(); security.SetOwner(user);
        security.SetAccessRuleProtection(true, false);
        security.AddAccessRule(new FileSystemAccessRule(user, FileSystemRights.FullControl, AccessControlType.Allow));
        using (var stream = new FileStream(path, FileMode.CreateNew, FileSystemRights.FullControl,
            FileShare.None, 4096, FileOptions.None, security)) {
            stream.Write(bytes, 0, bytes.Length); stream.Flush(); Verify(stream.SafeFileHandle);
        }
    }
}
'@
if ($Operation -eq 'read') {
    [Console]::Out.Write([Convert]::ToBase64String([Shadow6KeyFile]::Read($KeyPath)))
} else {
    $buffer = New-Object char[] 45
    $count = [Console]::In.ReadBlock($buffer, 0, 45)
    if ($count -ne 44) { throw 'invalid key input length' }
    [Shadow6KeyFile]::Create($KeyPath, [Convert]::FromBase64String((-join $buffer[0..43])))
}
