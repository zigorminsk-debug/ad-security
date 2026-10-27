using System.Runtime.InteropServices;
using System.Text;

namespace AdTrustRepair.Native;

/// <summary>Расшифровка DPAPI-блобов (машинный контекст).</summary>
internal static class Dpapi
{
    private const uint CryptProtectUiForbidden = 0x1;
    private const uint CryptProtectLocalMachine = 0x4;

    [StructLayout(LayoutKind.Sequential)]
    private struct DataBlob
    {
        public int cbData;
        public IntPtr pbData;
    }

    public static byte[] Unprotect(byte[] encrypted)
    {
        var input = new DataBlob();
        var output = new DataBlob();
        IntPtr inputBuffer = IntPtr.Zero;

        try
        {
            inputBuffer = Marshal.AllocHGlobal(encrypted.Length);
            Marshal.Copy(encrypted, 0, inputBuffer, encrypted.Length);
            input.pbData = inputBuffer;
            input.cbData = encrypted.Length;

            if (!CryptUnprotectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectUiForbidden, out output))
            {
                int error = Marshal.GetLastPInvokeError();
                throw new InvalidOperationException(
                    $"CryptUnprotectData: ошибка {error}. " +
                    "Похоже, блоб зашифрован для другого контекста (нужен SYSTEM этой машины).");
            }

            var result = new byte[output.cbData];
            if (output.cbData > 0) Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            if (output.pbData != IntPtr.Zero) LocalFree(output.pbData);
            if (inputBuffer != IntPtr.Zero) Marshal.FreeHGlobal(inputBuffer);
        }
    }

    public static string UnprotectToText(byte[] encrypted)
        => Encoding.UTF8.GetString(Unprotect(encrypted));

    /// <summary>Шифрует данные в контексте машины (как это делает Windows для секретов).</summary>
    public static byte[] Protect(byte[] plain)
    {
        var input = new DataBlob();
        var output = new DataBlob();
        IntPtr inputBuffer = IntPtr.Zero;

        try
        {
            inputBuffer = Marshal.AllocHGlobal(Math.Max(plain.Length, 1));
            Marshal.Copy(plain, 0, inputBuffer, plain.Length);
            input.pbData = inputBuffer;
            input.cbData = plain.Length;

            if (!CryptProtectData(ref input, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero, IntPtr.Zero,
                    CryptProtectLocalMachine | CryptProtectUiForbidden, out output))
            {
                int error = Marshal.GetLastPInvokeError();
                throw new InvalidOperationException($"CryptProtectData: ошибка {error}.");
            }

            var result = new byte[output.cbData];
            if (output.cbData > 0) Marshal.Copy(output.pbData, result, 0, output.cbData);
            return result;
        }
        finally
        {
            if (output.pbData != IntPtr.Zero) LocalFree(output.pbData);
            if (inputBuffer != IntPtr.Zero) Marshal.FreeHGlobal(inputBuffer);
        }
    }

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptProtectData(
        ref DataBlob dataIn, IntPtr description, IntPtr entropy, IntPtr reserved,
        IntPtr promptStruct, uint flags, out DataBlob dataOut);

    [DllImport("crypt32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
    private static extern bool CryptUnprotectData(
        ref DataBlob dataIn, IntPtr description, IntPtr entropy, IntPtr reserved,
        IntPtr promptStruct, uint flags, out DataBlob dataOut);

    [DllImport("kernel32.dll")]
    private static extern IntPtr LocalFree(IntPtr handle);
}
