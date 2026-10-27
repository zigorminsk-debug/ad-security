using System.Runtime.InteropServices;
using System.Text;

namespace AdTrustRepair.Native;

internal enum NetJoinStatus
{
    NetSetupUnknownStatus = 0,
    NetSetupUnjoined = 1,
    NetSetupWorkgroupName = 2,
    NetSetupDomainName = 3
}

internal enum ComputerNameFormat
{
    ComputerNameNetBIOS = 0,
    ComputerNameDnsHostname = 1,
    ComputerNameDnsDomain = 2,
    ComputerNameDnsFullyQualified = 3,
    ComputerNamePhysicalNetBIOS = 4,
    ComputerNamePhysicalDnsHostname = 5,
    ComputerNamePhysicalDnsDomain = 6,
    ComputerNamePhysicalDnsFullyQualified = 7
}

[Flags]
internal enum TokenAccess : uint
{
    TokenAssignPrimary = 0x0001,
    TokenDuplicate = 0x0002,
    TokenQuery = 0x0008,
    TokenAdjustPrivileges = 0x0020,
    TokenAllAccess = 0xF01FF
}

internal enum SecurityImpersonationLevel
{
    SecurityAnonymous,
    SecurityIdentification,
    SecurityImpersonation,
    SecurityDelegation
}

internal enum TokenType
{
    TokenPrimary = 1,
    TokenImpersonation = 2
}

[StructLayout(LayoutKind.Sequential)]
internal struct LsaUnicodeString
{
    public ushort Length;
    public ushort MaximumLength;
    public IntPtr Buffer;
}

internal static class NativeMethods
{
    // ---------- NetAPI32 ----------
    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    internal static extern int NetGetJoinInformation(
        string? server, out IntPtr nameBuffer, out NetJoinStatus status);

    [DllImport("netapi32.dll")]
    internal static extern int NetApiBufferFree(IntPtr buffer);

    // ---------- KERNEL32 ----------
    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool GetComputerNameEx(
        ComputerNameFormat nameType, StringBuilder buffer, ref int size);

    // ---------- ADVAPI32 ----------
    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr process, TokenAccess access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool DuplicateTokenEx(
        IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes,
        SecurityImpersonationLevel impersonationLevel, TokenType tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);
}
