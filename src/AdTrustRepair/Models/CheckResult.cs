namespace AdTrustRepair.Models;

public enum CheckStatus
{
    Ok,
    Info,
    Warning,
    Error,
    NotApplicable
}

public sealed class CheckResult
{
    public string Id { get; init; } = "";
    public string Category { get; init; } = "";
    public string Title { get; init; } = "";
    public string Summary { get; init; } = "";
    public string Details { get; init; } = "";
    public CheckStatus Status { get; set; } = CheckStatus.Info;
    public TimeSpan Duration { get; set; }

    public string StatusText => Status switch
    {
        CheckStatus.Ok => "OK",
        CheckStatus.Info => "Информация",
        CheckStatus.Warning => "Внимание",
        CheckStatus.Error => "Ошибка",
        CheckStatus.NotApplicable => "Не применимо",
        _ => "—"
    };
}

public sealed class ScanReport
{
    public DateTime StartedLocal { get; set; } = DateTime.Now;
    public DateTime FinishedLocal { get; set; } = DateTime.Now;
    public List<CheckResult> Checks { get; } = new();

    public bool IsDomainJoined { get; set; }
    public string DomainName { get; set; } = "";
    public string NetBiosDomain { get; set; } = "";
    public string ComputerName { get; set; } = "";
    public string Fqdn { get; set; } = "";

    public bool? SecureChannelOk { get; set; }
    public bool? KerberosOk { get; set; }
    public bool? DnsOk { get; set; }
    public bool? DcReachable { get; set; }
    public bool? TimeSkewOk { get; set; }
    public string? DomainController { get; set; }
    public string? SecureChannelMessage { get; set; }

    public List<string> Recommendations { get; } = new();

    public bool TrustBroken => IsDomainJoined && SecureChannelOk == false;

    public bool TrustHealthy => IsDomainJoined && SecureChannelOk == true;

    public CheckStatus OverallStatus
    {
        get
        {
            if (!IsDomainJoined) return CheckStatus.NotApplicable;
            if (SecureChannelOk == false) return CheckStatus.Error;
            if (Checks.Any(c => c.Status == CheckStatus.Error)) return CheckStatus.Error;
            if (Checks.Any(c => c.Status == CheckStatus.Warning)) return CheckStatus.Warning;
            return CheckStatus.Ok;
        }
    }

    public string OverallTitle => OverallStatus switch
    {
        CheckStatus.Ok => "Доверие в порядке",
        CheckStatus.Warning => "Доверие работает, есть замечания",
        CheckStatus.Error => TrustBroken ? "Доверие нарушено" : "Обнаружены ошибки",
        CheckStatus.NotApplicable => "Компьютер не в домене",
        _ => "Неизвестно"
    };

    public int Count(CheckStatus status) => Checks.Count(c => c.Status == status);
}
