using System.Runtime.InteropServices;
using System.Text;
using AdTrustRepair.Native;

namespace AdTrustRepair.Services;

internal sealed record ComputerIdentity(string DnsHostName, string DnsDomain, string Fqdn, string NetBiosName);

/// <summary>Сведения о домене, компьютере и способе его «присоединения».</summary>
internal static class MachineInfo
{
    public static ComputerIdentity GetIdentity()
    {
        return new ComputerIdentity(
            GetComputerNameEx(ComputerNameFormat.ComputerNameDnsHostname),
            GetComputerNameEx(ComputerNameFormat.ComputerNameDnsDomain),
            GetComputerNameEx(ComputerNameFormat.ComputerNameDnsFullyQualified),
            GetComputerNameEx(ComputerNameFormat.ComputerNameNetBIOS));
    }

    public static (NetJoinStatus Status, string Name) GetJoinInformation()
    {
        int result = NativeMethods.NetGetJoinInformation(null, out IntPtr buffer, out NetJoinStatus status);
        string name = "";
        if (result == 0 && buffer != IntPtr.Zero)
        {
            name = Marshal.PtrToStringUni(buffer) ?? "";
            NativeMethods.NetApiBufferFree(buffer);
        }

        return (status, name);
    }

    public static bool IsDomainJoined(out string domain)
    {
        var (status, name) = GetJoinInformation();
        domain = name;
        return status == NetJoinStatus.NetSetupDomainName && name.Length > 0;
    }

    private static string GetComputerNameEx(ComputerNameFormat format)
    {
        var buffer = new StringBuilder(512);
        int size = buffer.Capacity;
        return NativeMethods.GetComputerNameEx(format, buffer, ref size) ? buffer.ToString() : "";
    }

    /// <summary>NetBIOS-имя домена (если DNS-имя длинное или недоступно).</summary>
    public static string NormalizeDomainName(string domain)
    {
        if (string.IsNullOrWhiteSpace(domain)) return "";
        if (!domain.Contains('.')) return domain;
        int dot = domain.IndexOf('.');
        return domain[..dot].ToUpperInvariant();
    }
}

/// <summary>Установка пароля учётной записи компьютера через NetUserSetInfo.</summary>
internal static class NetUser
{
    private const int UserInfoPassword = 1003; // USER_INFO_1003

    [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
    private struct UserInfo1003
    {
        [MarshalAs(UnmanagedType.LPWStr)] public string Password;
    }

    public static void SetPassword(string computerAccount, string password)
    {
        var info = new UserInfo1003 { Password = password };
        int status = NetUserSetInfo(null, computerAccount, UserInfoPassword, ref info, out _);
        if (status != 0)
            throw new InvalidOperationException(
                "NetUserSetInfo: " + new System.ComponentModel.Win32Exception(status).Message +
                $" (код {status}). Возможно, у текущей учётной записи нет прав на смену пароля компьютера.");
    }

    [DllImport("netapi32.dll", CharSet = CharSet.Unicode)]
    private static extern int NetUserSetInfo(string? server, string userName, int level, ref UserInfo1003 buffer,
        out int errorParameter);
}
