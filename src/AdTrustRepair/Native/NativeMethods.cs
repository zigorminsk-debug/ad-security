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

[Flags]
internal enum LogonFlags : uint
{
    LogonWithProfile = 1,
    LogonNetCredentialsOnly = 2
}

[Flags]
internal enum CreateProcessFlags : uint
{
    CreateUnicodeEnvironment = 0x00000400,
    CreateNewConsole = 0x00000010,
    CreateNoWindow = 0x08000000
}

[StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
internal struct StartupInfo
{
    public int cb;
    public string? lpReserved;
    public string? lpDesktop;
    public string? lpTitle;
    public int dwX;
    public int dwY;
    public int dwXSize;
    public int dwYSize;
    public int dwXCountChars;
    public int dwYCountChars;
    public int dwFillAttribute;
    public int dwFlags;
    public short wShowWindow;
    public short cbReserved2;
    public IntPtr lpReserved2;
    public IntPtr hStdInput;
    public IntPtr hStdOutput;
    public IntPtr hStdError;
}

[StructLayout(LayoutKind.Sequential)]
internal struct ProcessInformation
{
    public IntPtr hProcess;
    public IntPtr hThread;
    public int dwProcessId;
    public int dwThreadId;
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

    [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool Wow64RevertWow64FsRedirection(out IntPtr oldValue);

    // ---------- ADVAPI32 ----------
    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool LogonUser(
        string userName, string? domain, string password, int logonType, int logonProvider,
        out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool OpenProcessToken(IntPtr process, TokenAccess access, out IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool DuplicateTokenEx(
        IntPtr existingToken, uint desiredAccess, IntPtr tokenAttributes,
        SecurityImpersonationLevel impersonationLevel, TokenType tokenType, out IntPtr newToken);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CreateProcessAsUser(
        IntPtr token, string? applicationName, string commandLine,
        IntPtr processAttributes, IntPtr threadAttributes, bool inheritHandles,
        CreateProcessFlags creationFlags, IntPtr environment, string? currentDirectory,
        ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("advapi32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    internal static extern bool CreateProcessWithLogonW(
        string userName, string? domain, string password, LogonFlags logonFlags,
        string? applicationName, string commandLine, CreateProcessFlags creationFlags,
        IntPtr environment, string? currentDirectory,
        ref StartupInfo startupInfo, out ProcessInformation processInformation);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern bool CloseHandle(IntPtr handle);

    // ---------- USERENV ----------
    [DllImport("userenv.dll", SetLastError = true)]
    internal static extern bool CreateEnvironmentBlock(out IntPtr environment, IntPtr token, bool inherit);

    [DllImport("userenv.dll", SetLastError = true)]
    internal static extern bool DestroyEnvironmentBlock(IntPtr environment);

    // ---------- SHELL32 ----------
    [DllImport("shell32.dll", CharSet = CharSet.Unicode)]
    internal static extern bool ShellExecuteEx(ref ShellExecuteInfo info);

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    internal struct ShellExecuteInfo
    {
        public int cbSize;
        public uint fMask;
        public IntPtr hwnd;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpVerb;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpFile;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpParameters;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpDirectory;
        public int nShow;
        public IntPtr hInstApp;
        public IntPtr lpIDList;
        [MarshalAs(UnmanagedType.LPWStr)] public string lpClass;
        public IntPtr hkeyClass;
        public uint dwHotKey;
        public IntPtr hIcon;
        public IntPtr hProcess;
    }

    internal const uint SeeMaskNoCloseProcess = 0x00000040;
    internal const int SwShowNormal = 1;
}
