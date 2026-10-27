using System.Text;

namespace AdTrustRepair.Services;

/// <summary>Простой журнал приложения: в памяти, в файл и в UI.</summary>
internal static class AppLog
{
    private static readonly object Sync = new();
    private static readonly StringBuilder Buffer = new();
    private static string? _logFile;

    public static event Action<string>? LineAdded;

    public static string FilePath
    {
        get
        {
            if (_logFile != null) return _logFile;
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AdTrustRepair", "Logs");
            try
            {
                Directory.CreateDirectory(dir);
                _logFile = Path.Combine(dir, $"adtrustrepair-{DateTime.Now:yyyyMMdd-HHmmss}.log");
            }
            catch
            {
                _logFile = Path.Combine(Path.GetTempPath(), "adtrustrepair.log");
            }

            return _logFile!;
        }
    }

    public static void Write(string message)
    {
        string line = $"[{DateTime.Now:HH:mm:ss}] {message}";
        lock (Sync)
        {
            Buffer.AppendLine(line);
            try
            {
                File.AppendAllText(FilePath, line + Environment.NewLine, Encoding.UTF8);
            }
            catch
            {
                // журнал не должен ломать основную работу
            }
        }

        LineAdded?.Invoke(line);
    }

    public static string ReadAll()
    {
        lock (Sync) return Buffer.ToString();
    }
}
