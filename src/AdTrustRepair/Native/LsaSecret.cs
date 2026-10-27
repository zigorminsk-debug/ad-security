using System.ComponentModel;
using System.Runtime.InteropServices;
using System.Text;

namespace AdTrustRepair.Native;

/// <summary>
/// Работа с LSA-секретами компьютера. Именно здесь Windows хранит учётные данные
/// доменной учётной записи компьютера (полный набор: <c>$MACHINE.ACC</c> и
/// <c>SECRETS\MACHINE.ACC</c>), зашифрованные DPAPI в контексте машины.
/// </summary>
internal static class LsaSecret
{
    /// <summary>Полный (не «обрезанный») секрет учётной записи компьютера.</summary>
    public const string MachineAccountSecretPath = "$MACHINE.ACC";

    /// <summary>Второе место хранения тех же данных (используется частью подсистем).</summary>
    public const string SecretsMachineAccountPath = @"SECRETS\MACHINE.ACC";

    private const uint PolicyGetPrivateInformation = 0x00000004;
    private const uint PolicyCreateSecret = 0x00000020;
    private const int ErrorSuccess = 0;

    [StructLayout(LayoutKind.Sequential)]
    private struct LsaObjectAttributes
    {
        public int Length;
        public IntPtr RootDirectory;
        public IntPtr ObjectName;
        public uint Attributes;
        public IntPtr SecurityDescriptor;
        public IntPtr SecurityQualityOfService;
    }

    /// <summary>Читает сырые байты секрета (как правило — DPAPI-блоб).</summary>
    public static byte[] Read(string secretPath)
    {
        IntPtr policy = IntPtr.Zero;
        IntPtr data = IntPtr.Zero;
        try
        {
            policy = OpenPolicy(PolicyGetPrivateInformation);

            int keyNameBufferSize = (secretPath.Length + 1) * 2;
            IntPtr keyNameBuffer = Marshal.StringToHGlobalUni(secretPath);
            var keyName = new LsaUnicodeString
            {
                Buffer = keyNameBuffer,
                Length = (ushort)(secretPath.Length * 2),
                MaximumLength = (ushort)keyNameBufferSize
            };

            try
            {
                int status = LsaRetrievePrivateData(policy, ref keyName, out data);
                ThrowIfError(status, "LsaRetrievePrivateData(" + secretPath + ")");

                var lsaString = Marshal.PtrToStructure<LsaUnicodeString>(data);
                if (lsaString.Length == 0 || lsaString.Buffer == IntPtr.Zero) return Array.Empty<byte>();
                var result = new byte[lsaString.Length];
                Marshal.Copy(lsaString.Buffer, result, 0, lsaString.Length);
                return result;
            }
            finally
            {
                Marshal.FreeHGlobal(keyNameBuffer);
            }
        }
        finally
        {
            if (data != IntPtr.Zero) LsaFreeMemory(data);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }

    /// <summary>Записывает (перезаписывает) секрет.</summary>
    public static void Write(string secretPath, byte[] value)
    {
        IntPtr policy = IntPtr.Zero;
        IntPtr keyNameBuffer = IntPtr.Zero;
        IntPtr valueBuffer = IntPtr.Zero;
        try
        {
            policy = OpenPolicy(PolicyCreateSecret);

            keyNameBuffer = Marshal.StringToHGlobalUni(secretPath);
            var keyName = new LsaUnicodeString
            {
                Buffer = keyNameBuffer,
                Length = (ushort)(secretPath.Length * 2),
                MaximumLength = (ushort)((secretPath.Length + 1) * 2)
            };

            valueBuffer = Marshal.AllocHGlobal(Math.Max(value.Length, 1));
            Marshal.Copy(value, 0, valueBuffer, value.Length);
            var data = new LsaUnicodeString
            {
                Buffer = valueBuffer,
                Length = (ushort)value.Length,
                MaximumLength = (ushort)value.Length
            };

            int status = LsaStorePrivateData(policy, ref keyName, ref data);
            ThrowIfError(status, "LsaStorePrivateData(" + secretPath + ")");
        }
        finally
        {
            if (keyNameBuffer != IntPtr.Zero) Marshal.FreeHGlobal(keyNameBuffer);
            if (valueBuffer != IntPtr.Zero) Marshal.FreeHGlobal(valueBuffer);
            if (policy != IntPtr.Zero) LsaClose(policy);
        }
    }

    public static void Write(string secretPath, string user, string password)
        => Write(secretPath, BuildSecretBlob(user, password));

    /// <summary>Содержимое секрета: "DOMAIN\COMPUTER$\nПАРОЛЬ" в UTF-8.</summary>
    public static byte[] BuildSecretBlob(string user, string password)
    {
        var text = user + "\n" + password;
        return Encoding.UTF8.GetBytes(text);
    }

    /// <summary>Разбирает расшифрованное содержимое секрета на пользователя и пароль.</summary>
    public static (string User, string Password)? ParseSecret(string decrypted)
    {
        if (string.IsNullOrEmpty(decrypted)) return null;
        int index = decrypted.IndexOf('\n');
        if (index < 0)
        {
            // некоторые версии хранят "user password"
            index = decrypted.IndexOf('\r');
            if (index < 0) return null;
        }

        string user = decrypted[..index].TrimEnd('\r');
        string password = decrypted[(index + 1)..].TrimEnd('\r', '\n');
        return (user, password);
    }

    private static IntPtr OpenPolicy(uint access)
    {
        var attributes = new LsaObjectAttributes { Length = Marshal.SizeOf<LsaObjectAttributes>() };
        int status = LsaOpenPolicy(IntPtr.Zero, ref attributes, access, out IntPtr policy);
        ThrowIfError(status, "LsaOpenPolicy");
        return policy;
    }

    private static void ThrowIfError(int status, string operation)
    {
        if (status == ErrorSuccess) return;
        int win32 = LsaNtStatusToWinError(status);
        string message;
        try
        {
            message = new Win32Exception(win32).Message;
        }
        catch
        {
            message = "неизвестная ошибка";
        }

        throw new InvalidOperationException(
            $"{operation}: NTSTATUS 0x{status:X8}, Win32 {win32} ({message}).");
    }

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaOpenPolicy(IntPtr systemName, ref LsaObjectAttributes attributes,
        uint accessMask, out IntPtr policyHandle);

    [DllImport("advapi32.dll", SetLastError = true)]
    private static extern int LsaRetrievePrivateData(IntPtr policyHandle, ref LsaUnicodeString keyName,
        out IntPtr privateData);

    [DllImport("advapi32.dll", SetLastError = true)]
    internal static extern int LsaStorePrivateData(IntPtr policyHandle, ref LsaUnicodeString keyName,
        ref LsaUnicodeString privateData);

    [DllImport("advapi32.dll")]
    private static extern int LsaClose(IntPtr handle);

    [DllImport("advapi32.dll")]
    private static extern int LsaFreeMemory(IntPtr buffer);

    [DllImport("advapi32.dll")]
    private static extern int LsaNtStatusToWinError(int status);
}
