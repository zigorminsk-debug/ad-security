using System.Diagnostics;
using System.Text;

namespace AdTrustRepair.Services;

internal sealed record CommandResult(int ExitCode, string StdOut, string StdErr, bool TimedOut)
{
    public bool Success => !TimedOut && ExitCode == 0;

    public string Combined
    {
        get
        {
            var parts = new List<string>();
            if (!string.IsNullOrWhiteSpace(StdOut)) parts.Add(StdOut.Trim());
            if (!string.IsNullOrWhiteSpace(StdErr)) parts.Add(StdErr.Trim());
            if (TimedOut) parts.Add("(команда прервана по таймауту)");
            return string.Join(Environment.NewLine, parts);
        }
    }

    public string FirstLine
    {
        get
        {
            foreach (var raw in Combined.Split('\n'))
            {
                string s = raw.Trim();
                if (s.Length > 0) return s;
            }

            return "";
        }
    }

    public static CommandResult FromText(int exitCode, string text) => new(exitCode, text, "", false);
}

/// <summary>Запуск консольных утилит с захватом вывода, таймаутом и скрытым окном.</summary>
internal static class ProcessRunner
{
    public static string System32(string fileName)
        => Path.Combine(Environment.GetFolderPath(Environment.SpecialFolder.System), fileName);

    public static Task<CommandResult> RunAsync(
        string fileName,
        string arguments,
        TimeSpan? timeout = null,
        string? workingDirectory = null,
        string? stdin = null,
        bool logCommand = true,
        CancellationToken cancellationToken = default,
        IReadOnlyDictionary<string, string>? environment = null)
    {
        return Task.Run(() => Run(fileName, arguments, timeout, workingDirectory, stdin, logCommand,
                environment, cancellationToken),
            cancellationToken);
    }

    private static CommandResult Run(
        string fileName, string arguments, TimeSpan? timeout, string? workingDirectory,
        string? stdin, bool logCommand, IReadOnlyDictionary<string, string>? environment,
        CancellationToken cancellationToken)
    {
        var psi = new ProcessStartInfo
        {
            FileName = fileName,
            Arguments = arguments,
            UseShellExecute = false,
            RedirectStandardOutput = true,
            RedirectStandardError = true,
            RedirectStandardInput = stdin != null,
            CreateNoWindow = true,
            WorkingDirectory = workingDirectory ?? Environment.SystemDirectory,
            StandardOutputEncoding = Encoding.UTF8,
            StandardErrorEncoding = Encoding.UTF8
        };

        if (environment != null)
        {
            foreach (var (key, value) in environment)
                psi.Environment[key] = value;
        }

        if (logCommand) AppLog.Write("$ " + Path.GetFileName(fileName) + " " + arguments);

        using var process = new Process { StartInfo = psi };
        var stdout = new StringBuilder();
        var stderr = new StringBuilder();
        using var outDone = new AutoResetEvent(false);
        using var errDone = new AutoResetEvent(false);

        process.OutputDataReceived += (_, e) =>
        {
            if (e.Data == null) outDone.Set();
            else lock (stdout) stdout.AppendLine(e.Data);
        };
        process.ErrorDataReceived += (_, e) =>
        {
            if (e.Data == null) errDone.Set();
            else lock (stderr) stderr.AppendLine(e.Data);
        };

        try
        {
            process.Start();
        }
        catch (Exception ex)
        {
            AppLog.Write("Не удалось запустить " + fileName + ": " + ex.Message);
            return new CommandResult(-1, "", ex.Message, false);
        }

        process.BeginOutputReadLine();
        process.BeginErrorReadLine();

        if (stdin != null)
        {
            try
            {
                process.StandardInput.WriteLine(stdin);
                process.StandardInput.Flush();
                process.StandardInput.Close();
            }
            catch
            {
                // процесс мог завершиться раньше
            }
        }

        var limit = timeout ?? TimeSpan.FromSeconds(90);
        bool finished = process.WaitForExit((int)limit.TotalMilliseconds);
        if (!finished)
        {
            try
            {
                process.Kill(entireProcessTree: true);
            }
            catch
            {
                // ignore
            }

            return new CommandResult(-1, stdout.ToString(), stderr.ToString(), true);
        }

        outDone.WaitOne(2000);
        errDone.WaitOne(2000);
        int exitCode;
        try
        {
            exitCode = process.ExitCode;
        }
        catch
        {
            exitCode = -1;
        }

        string so, se;
        lock (stdout) so = stdout.ToString();
        lock (stderr) se = stderr.ToString();

        if (logCommand)
        {
            foreach (var line in (so + Environment.NewLine + se)
                         .Split('\n', StringSplitOptions.RemoveEmptyEntries | StringSplitOptions.TrimEntries))
                AppLog.Write("   " + line);
        }

        cancellationToken.ThrowIfCancellationRequested();
        return new CommandResult(exitCode, so, se, false);
    }

    /// <summary>Запуск PowerShell с выводом только JSON/текста (без баннеров и прогресса).</summary>
    public static Task<CommandResult> PowerShellAsync(string script, TimeSpan? timeout = null,
        CancellationToken cancellationToken = default,
        IReadOnlyDictionary<string, string>? environment = null,
        bool logScript = false)
    {
        string encoded = Convert.ToBase64String(Encoding.Unicode.GetBytes(script));
        string args = "-NoLogo -NoProfile -NonInteractive -ExecutionPolicy Bypass -EncodedCommand " + encoded;
        return RunAsync(System32(@"WindowsPowerShell\v1.0\powershell.exe"), args,
            timeout ?? TimeSpan.FromSeconds(120), logCommand: logScript,
            cancellationToken: cancellationToken, environment: environment);
    }
}
