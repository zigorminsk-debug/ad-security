using System.Diagnostics;
using System.Security.Principal;
using AdTrustRepair.Services;
using AdTrustRepair.UI;

namespace AdTrustRepair;

internal static class Program
{
    internal const string AppTitle = "AD Trust Repair — восстановление доверия к домену";

    [STAThread]
    private static void Main()
    {
        Application.SetHighDpiMode(HighDpiMode.PerMonitorV2);
        Application.EnableVisualStyles();
        Application.SetCompatibleTextRenderingDefault(false);

        Application.ThreadException += (_, e) => ShowFatal(e.Exception);
        AppDomain.CurrentDomain.UnhandledException += (_, e) => ShowFatal(e.ExceptionObject as Exception);

        if (!IsElevated())
        {
            var answer = MessageBox.Show(
                "Программа должна быть запущена от имени администратора.\n\n" +
                "Перезапустить с повышением прав?",
                AppTitle, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer == DialogResult.Yes)
                RelaunchElevated();
            return;
        }

        Application.Run(new MainForm());
    }

    internal static bool IsElevated()
    {
        try
        {
            using var identity = WindowsIdentity.GetCurrent();
            return new WindowsPrincipal(identity).IsInRole(WindowsBuiltInRole.Administrator);
        }
        catch
        {
            return false;
        }
    }

    private static void RelaunchElevated()
    {
        try
        {
            string exe = Environment.ProcessPath ?? Application.ExecutablePath;
            Process.Start(new ProcessStartInfo(exe)
            {
                UseShellExecute = true,
                Verb = "runas"
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show("Не удалось перезапустить с повышением прав: " + ex.Message,
                AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private static void ShowFatal(Exception? ex)
    {
        AppLog.Write("НЕОБРАБОТАННОЕ ИСКЛЮЧЕНИЕ: " + ex);
        MessageBox.Show("Произошла непредвиденная ошибка:\n\n" + (ex?.Message ?? "неизвестная ошибка") +
                        "\n\nПодробности записаны в журнал приложения.",
            AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Error);
    }
}
