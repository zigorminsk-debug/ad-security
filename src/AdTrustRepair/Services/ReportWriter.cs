using System.Text;
using AdTrustRepair.Models;

namespace AdTrustRepair.Services;

internal static class ReportWriter
{
    public static string ToText(ScanReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("AD Trust Repair — отчёт о диагностике");
        sb.AppendLine("=====================================");
        sb.AppendLine($"Дата: {report.StartedLocal:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Компьютер: {report.ComputerName} ({report.Fqdn})");
        sb.AppendLine($"Домен: {(report.IsDomainJoined ? report.DomainName : "не в домене")}");
        sb.AppendLine($"Контроллер домена: {report.DomainController ?? "—"}");
        sb.AppendLine($"Итог: {report.OverallTitle}");
        sb.AppendLine($"Защищённый канал: {FormatBool(report.SecureChannelOk)}");
        sb.AppendLine($"Kerberos (krbtgt): {FormatBool(report.KerberosOk)}");
        sb.AppendLine($"DNS: {FormatBool(report.DnsOk)}");
        sb.AppendLine($"Доступность контроллера: {FormatBool(report.DcReachable)}");
        sb.AppendLine($"Синхронизация времени: {FormatBool(report.TimeSkewOk)}");
        sb.AppendLine($"Проверок: {report.Checks.Count}, ошибок: {report.Count(CheckStatus.Error)}, " +
                      $"предупреждений: {report.Count(CheckStatus.Warning)}");
        sb.AppendLine();

        foreach (var group in report.Checks.GroupBy(c => c.Category))
        {
            sb.AppendLine("[" + group.Key + "]");
            foreach (var check in group)
            {
                sb.AppendLine($"  {check.StatusText,-11} {check.Title}");
                sb.AppendLine($"              {check.Summary}");
                if (!string.IsNullOrWhiteSpace(check.Details))
                {
                    foreach (var line in check.Details.Split('\n'))
                        sb.AppendLine("              | " + line.TrimEnd('\r'));
                }

                sb.AppendLine();
            }
        }

        sb.AppendLine("Рекомендации:");
        foreach (var rec in report.Recommendations) sb.AppendLine("  - " + rec);

        sb.AppendLine();
        sb.AppendLine("Журнал выполнения:");
        sb.AppendLine(AppLog.ReadAll());
        return sb.ToString();
    }

    public static string ToText(RepairReport report)
    {
        var sb = new StringBuilder();
        sb.AppendLine("AD Trust Repair — отчёт о восстановлении");
        sb.AppendLine("========================================");
        sb.AppendLine($"Начало: {report.StartedLocal:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Окончание: {report.FinishedLocal:yyyy-MM-dd HH:mm:ss}");
        sb.AppendLine($"Способ: {report.MethodUsed ?? "—"}");
        sb.AppendLine($"Пароль компьютера сброшен: {(report.MachinePasswordReset ? "да" : "нет")}");
        sb.AppendLine($"Доверие восстановлено: {FormatBool(report.TrustRestored)}");
        sb.AppendLine($"Проверка: {report.VerificationMessage ?? "—"}");
        if (!string.IsNullOrEmpty(report.ErrorMessage)) sb.AppendLine($"Ошибка: {report.ErrorMessage}");
        sb.AppendLine();
        foreach (var step in report.Steps)
        {
            string mark = step.Skipped ? "[пропуск]" : step.Success ? "[успех]" : "[ошибка]";
            sb.AppendLine($"{mark} {step.Title}");
            sb.AppendLine("        " + step.Message);
        }

        return sb.ToString();
    }

    private static string FormatBool(bool? value) => value switch
    {
        true => "да",
        false => "нет",
        _ => "неизвестно"
    };
}
