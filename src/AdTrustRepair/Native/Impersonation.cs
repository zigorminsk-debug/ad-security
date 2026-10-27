using System.Diagnostics;
using System.Runtime.InteropServices;
using AdTrustRepair.Services;

namespace AdTrustRepair.Native;

/// <summary>
/// Временное олицетворение SYSTEM через токен процесса winlogon.
/// Нужно для доступа к LSA-секрету компьютера и к DPAPI-ключам машины.
/// </summary>
internal sealed class Impersonation : IDisposable
{
    private readonly IntPtr _token;
    private bool _impersonating;

    private Impersonation(IntPtr token)
    {
        _token = token;
    }

    public static Impersonation AsSystem()
    {
        EnableDebugPrivilege();
        int pid = FindWinlogonPid();
        using var winlogon = Process.GetProcessById(pid);
        if (!NativeMethods.OpenProcessToken(winlogon.Handle,
                TokenAccess.TokenDuplicate | TokenAccess.TokenAssignPrimary | TokenAccess.TokenQuery,
                out IntPtr token))
            throw new InvalidOperationException(
                "OpenProcessToken(winlogon) не удался: " + Marshal.GetLastPInvokeError());

        try
        {
            if (!NativeMethods.DuplicateTokenEx(token, (uint)TokenAccess.TokenAllAccess, IntPtr.Zero,
                    SecurityImpersonationLevel.SecurityImpersonation, TokenType.TokenPrimary, out IntPtr dup))
                throw new InvalidOperationException(
                    "DuplicateTokenEx не удался: " + Marshal.GetLastPInvokeError());

            var imp = new Impersonation(dup);
            imp.Enter();
            return imp;
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    private void Enter()
    {
        if (!SetThreadToken(IntPtr.Zero, _token))
            throw new InvalidOperationException("SetThreadToken не удался: " + Marshal.GetLastPInvokeError());
        _impersonating = true;
        AppLog.Write("Выполняется олицетворение SYSTEM.");
    }

    private static int FindWinlogonPid()
    {
        int currentSession = Process.GetCurrentProcess().SessionId;
        foreach (var name in new[] { "winlogon", "services" })
        {
            var candidates = Process.GetProcessesByName(name);
            try
            {
                foreach (var p in candidates)
                {
                    if (p.SessionId == currentSession) return p.Id;
                }

                if (candidates.Length > 0) return candidates[0].Id;
            }
            finally
            {
                foreach (var p in candidates) p.Dispose();
            }
        }

        throw new InvalidOperationException("Не найден SYSTEM-процесс — олицетворение SYSTEM невозможно.");
    }

    /// <summary>Без SeDebugPrivilege нельзя открыть токен winlogon.</summary>
    private static void EnableDebugPrivilege()
    {
        if (!NativeMethods.OpenProcessToken(GetCurrentProcess(),
                TokenAccess.TokenAdjustPrivileges | TokenAccess.TokenQuery, out IntPtr token))
            return;

        try
        {
            if (!LookupPrivilegeValue(null, "SeDebugPrivilege", out Luid luid)) return;
            var privileges = new TokenPrivileges
            {
                PrivilegeCount = 1,
                Luid = luid,
                Attributes = SePrivilegeEnabled
            };
            AdjustTokenPrivileges(token, false, ref privileges, 0, IntPtr.Zero, IntPtr.Zero);
        }
        finally
        {
            NativeMethods.CloseHandle(token);
        }
    }

    private const uint SePrivilegeEnabled = 0x00000002;

    [StructLayout(LayoutKind.Sequential)]
    private struct Luid
    {
        public uint LowPart;
        public int HighPart;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct TokenPrivileges
    {
        public uint PrivilegeCount;
        public Luid Luid;
        public uint Attributes;
    }

    [DllImport("kernel32.dll")]
    private static extern IntPtr GetCurrentProcess();

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool LookupPrivilegeValue(string? systemName, string name, out Luid luid);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool AdjustTokenPrivileges(IntPtr token, bool disableAllPrivileges,
        ref TokenPrivileges newState, int bufferLength, IntPtr previousState, IntPtr returnLength);

    public void Dispose()
    {
        if (_impersonating)
        {
            RevertToSelf();
            _impersonating = false;
        }

        if (_token != IntPtr.Zero) NativeMethods.CloseHandle(_token);
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool SetThreadToken(IntPtr thread, IntPtr token);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern bool RevertToSelf();
}
