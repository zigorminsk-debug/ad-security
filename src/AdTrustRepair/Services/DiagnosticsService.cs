using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;
using System.Text.Json;
using System.Text.RegularExpressions;
using AdTrustRepair.Models;
using AdTrustRepair.Native;

namespace AdTrustRepair.Services;

/// <summary>Диагностика состояния доверительных отношений компьютера с доменом.</summary>
public sealed class DiagnosticsService
{
    public event Action<CheckResult>? CheckCompleted;
    public event Action<string>? ProgressChanged;

    private sealed record Outcome(CheckStatus Status, string Summary, string Details);

    public async Task<ScanReport> ScanAsync(CancellationToken cancellationToken = default)
    {
        var report = new ScanReport { StartedLocal = DateTime.Now };
        AppLog.Write("=== Запуск диагностики ===");

        var identity = MachineInfo.GetIdentity();
        report.ComputerName = identity.NetBiosName;
        report.Fqdn = identity.Fqdn;

        await AddAsync(report, "system", "Система", "Операционная система и права", async () =>
        {
            var ps = ProcessRunner.System32(@"WindowsPowerShell\v1.0\powershell.exe");
            bool hasPs = File.Exists(ps);
            bool elevated = Program.IsElevated();
            string details =
                $"ОС: {RuntimeInformation.OSDescription}\r\n" +
                $"Версия: {Environment.OSVersion}\r\n" +
                $"64-битный процесс: {Environment.Is64BitProcess}\r\n" +
                $"PowerShell: {(hasPs ? ps : "не найден")}\r\n" +
                $"Права администратора: {(elevated ? "да" : "нет")}\r\n" +
                $"Пользователь: {Environment.UserDomainName}\\{Environment.UserName}";
            var status = hasPs && elevated ? CheckStatus.Ok : CheckStatus.Warning;
            string summary = !hasPs
                ? "PowerShell не найден — часть проверок недоступна"
                : !elevated
                    ? "Нет прав администратора — восстановление будет недоступно"
                    : "Windows, PowerShell и права администратора в порядке";
            await Task.CompletedTask;
            return new Outcome(status, summary, details);
        }, cancellationToken);

        var (joinStatus, joinName) = MachineInfo.GetJoinInformation();
        bool joined = joinStatus == NetJoinStatus.NetSetupDomainName && joinName.Length > 0;
        report.IsDomainJoined = joined;
        report.DomainName = joined
            ? (string.IsNullOrWhiteSpace(identity.DnsDomain) ? joinName : identity.DnsDomain)
            : (joinStatus == NetJoinStatus.NetSetupWorkgroupName ? joinName : "");

        await AddAsync(report, "system", "Домен", "Членство в домене", () =>
        {
            string details =
                $"Состояние: {DescribeJoinStatus(joinStatus)}\r\n" +
                $"Имя домена/рабочей группы: {(joinName.Length > 0 ? joinName : "—")}\r\n" +
                $"DNS-домен компьютера: {(identity.DnsDomain.Length > 0 ? identity.DnsDomain : "—")}\r\n" +
                $"FQDN: {(identity.Fqdn.Length > 0 ? identity.Fqdn : "—")}";
            return Task.FromResult(joined
                ? new Outcome(CheckStatus.Ok, $"Компьютер входит в домен {report.DomainName}", details)
                : new Outcome(CheckStatus.NotApplicable,
                    joinStatus == NetJoinStatus.NetSetupWorkgroupName
                        ? $"Компьютер в рабочей группе «{joinName}», доверие к домену не применяется"
                        : "Компьютер не входит в домен", details));
        }, cancellationToken);

        if (!joined)
        {
            report.Recommendations.Add(
                "Компьютер не входит в домен: восстанавливать доверие не требуется. " +
                "Если он должен быть в домене — выполните присоединение (Add-Computer).");
            report.FinishedLocal = DateTime.Now;
            return report;
        }

        string domain = report.DomainName;
        string netbios = MachineInfo.NormalizeDomainName(domain);
        string computerAccount = identity.NetBiosName + "$";
        string? dc = null;

        // ---------- DNS ----------
        await AddAsync(report, "network", "Сеть", "DNS: SRV-записи контроллеров домена", async () =>
        {
            var (ok, targets, error) = await LookupDcRecordsAsync(domain, cancellationToken);
            report.DnsOk = ok;
            bool domainResolves = false;
            string resolveInfo = "";
            try
            {
                var addresses = Dns.GetHostAddresses(domain);
                domainResolves = addresses.Length > 0;
                resolveInfo = $"Имя {domain} разрешается в: {string.Join(", ", addresses.Select(a => a.ToString()))}";
            }
            catch (Exception ex)
            {
                resolveInfo = $"Не удалось разрешить имя {domain}: {ex.Message}";
            }

            string details =
                $"Запрос: _ldap._tcp.dc._msdcs.{domain} (SRV)\r\n" +
                $"Найдено контроллеров: {targets.Count}\r\n" +
                (targets.Count > 0 ? "Контроллеры: " + string.Join(", ", targets) + "\r\n" : "") +
                resolveInfo + "\r\n" +
                (string.IsNullOrEmpty(error) ? "" : "Ошибка: " + error);

            if (!ok || targets.Count == 0)
                return new Outcome(CheckStatus.Error,
                    "DNS не находит контроллеры домена — это частая причина потери доверия", details);
            if (!domainResolves)
                return new Outcome(CheckStatus.Warning,
                    "SRV-записи найдены, но имя домена не разрешается", details);
            return new Outcome(CheckStatus.Ok, $"DNS в порядке, контроллеров найдено: {targets.Count}", details);
        }, cancellationToken);

        // ---------- DC discovery ----------
        await AddAsync(report, "network", "Сеть", "Поиск контроллера домена (nltest /dsgetdc)", async () =>
        {
            var res = await ProcessRunner.RunAsync(ProcessRunner.System32("nltest.exe"),
                "/dsgetdc:" + domain, TimeSpan.FromSeconds(40), cancellationToken: cancellationToken);
            var match = Regex.Match(res.Combined, @"\\\\(?<dc>[A-Za-z0-9._-]+)");
            if (match.Success) dc = match.Groups["dc"].Value;
            report.DomainController = dc;
            bool ok = res.Success && dc != null;
            string details = res.Combined;
            if (ok) details += $"\r\nИспользуемый контроллер: {dc}";
            return new Outcome(ok ? CheckStatus.Ok : CheckStatus.Error,
                ok ? $"Контроллер домена доступен: {dc}" : "Не удалось найти контроллер домена", details);
        }, cancellationToken);

        // ---------- Ping DC ----------
        await AddAsync(report, "network", "Сеть", "Доступность контроллера домена (ICMP)", async () =>
        {
            if (string.IsNullOrEmpty(dc))
            {
                report.DcReachable = false;
                return new Outcome(CheckStatus.Warning, "Контроллер не определён, проверка пропущена",
                    "Сначала должен успешно выполниться поиск контроллера домена.");
            }

            var res = await ProcessRunner.RunAsync("ping.exe", $"-n 2 -w 1500 {dc}",
                TimeSpan.FromSeconds(20), logCommand: false, cancellationToken: cancellationToken);
            report.DcReachable = res.Success;
            return new Outcome(res.Success ? CheckStatus.Ok : CheckStatus.Warning,
                res.Success ? $"Контроллер {dc} отвечает на ping" : $"Контроллер {dc} не отвечает на ping (ICMP может быть закрыт)",
                res.Combined);
        }, cancellationToken);

        // ---------- Secure channel ----------
        await AddAsync(report, "trust", "Доверие", "Проверка защищённого канала (Test-ComputerSecureChannel)", async () =>
        {
            var (ok, usedMethod, message, raw) = await TestSecureChannelAsync(domain, cancellationToken);
            report.SecureChannelOk = ok;
            report.SecureChannelMessage = message;
            if (ok == true)
                return new Outcome(CheckStatus.Ok, "Защищённый канал с доменом работает", raw);
            if (ok == false)
                return new Outcome(CheckStatus.Error,
                    "Доверительные отношения с доменом нарушены", raw);
            return new Outcome(CheckStatus.Warning,
                $"Не удалось проверить защищённый канал ({usedMethod})", raw);
        }, cancellationToken);

        // ---------- Kerberos ----------
        await AddAsync(report, "trust", "Доверие", "Получение Kerberos-билета (klist get krbtgt)", async () =>
        {
            string realm = domain.ToUpperInvariant();
            var res = await ProcessRunner.RunAsync(ProcessRunner.System32("klist.exe"),
                $"get krbtgt/{realm}", TimeSpan.FromSeconds(30), logCommand: false, cancellationToken: cancellationToken);
            report.KerberosOk = res.Success;
            string details = res.Combined +
                             $"\r\nКод возврата: {res.ExitCode}";
            if (res.Success)
                return new Outcome(CheckStatus.Ok, $"Билет krbtgt/{realm} получен — домен доверяет компьютеру", details);
            return new Outcome(report.DcReachable == false ? CheckStatus.Warning : CheckStatus.Error,
                $"Не удалось получить билет krbtgt/{realm}", details);
        }, cancellationToken);

        // ---------- Time skew ----------
        await AddAsync(report, "trust", "Доверие", "Расхождение времени с контроллером домена (Kerberos: 5 минут)", async () =>
        {
            if (string.IsNullOrEmpty(dc))
            {
                return new Outcome(CheckStatus.NotApplicable, "Контроллер не определён, проверка пропущена", "");
            }

            var res = await ProcessRunner.RunAsync(ProcessRunner.System32("w32tm.exe"),
                $"/stripchart /computer:{dc} /samples:1 /dataonly",
                TimeSpan.FromSeconds(25), logCommand: false, cancellationToken: cancellationToken);
            double? offset = ParseStripchartOffset(res.Combined);
            if (offset == null)
            {
                return new Outcome(CheckStatus.Info, "Не удалось измерить расхождение времени",
                    res.Combined + "\r\nСлужба «Windows Time» может быть остановлена.");
            }

            bool ok = Math.Abs(offset.Value) < 300;
            report.TimeSkewOk = ok;
            string details = $"Смещение: {offset.Value:+0.###;-0.###;0} c (порог Kerberos: 300 c)\r\n\r\n{res.Combined}";
            return new Outcome(ok ? CheckStatus.Ok : CheckStatus.Error,
                ok
                    ? $"Время синхронизировано (±{Math.Abs(offset.Value):0.#} c)"
                    : $"Время расходится с контроллером на {offset.Value:0.#} c — Kerberos не работает", details);
        }, cancellationToken);

        // ---------- Services ----------
        await AddAsync(report, "system", "Система", "Состояние служб", async () =>
        {
            const string script = """
                $names = @('Netlogon','LanmanWorkstation','LanmanServer','Dnscache','W32Time','Kdc')
                $out = foreach ($n in $names) {
                  $s = Get-Service -Name $n -ErrorAction SilentlyContinue
                  [pscustomobject]@{ Name = $n; Status = if ($s) { $s.Status.ToString() } else { 'NotFound' }; StartType = '' }
                }
                $out | ConvertTo-Json -Compress
                """;
            var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(60), cancellationToken);
            var items = ParseJsonArray(res.StdOut, res.Combined);
            var stopped = new List<string>();
            var lines = new List<string>();
            foreach (var item in items)
            {
                string name = GetString(item, "Name");
                string status = GetString(item, "Status");
                lines.Add($"{name}: {status}");
                if (status.Equals("Stopped", StringComparison.OrdinalIgnoreCase) && name != "Kdc")
                    stopped.Add(name);
            }

            string details = string.Join("\r\n", lines);
            if (stopped.Count == 0)
                return new Outcome(CheckStatus.Ok, "Службы, важные для домена, запущены", details);
            bool critical = stopped.Any(s => s.Equals("Netlogon", StringComparison.OrdinalIgnoreCase));
            return new Outcome(critical ? CheckStatus.Error : CheckStatus.Warning,
                "Остановлены службы: " + string.Join(", ", stopped), details);
        }, cancellationToken);

        // ---------- Policies ----------
        await AddAsync(report, "system", "Система", "Политики смены пароля компьютера", async () =>
        {
            const string script = """
                $out = [ordered]@{}
                $nl = 'HKLM:\SYSTEM\CurrentControlSet\Services\Netlogon\Parameters'
                try {
                  $p = Get-ItemProperty -Path $nl -ErrorAction Stop
                  $out.DisablePasswordChange = $p.DisablePasswordChange
                  $out.MaximumPasswordAge = $p.MaximumPasswordAge
                  $out.RequireSignOrSeal = $p.RequireSignOrSeal
                  $out.SealSecureChannel = $p.SealSecureChannel
                  $out.SignSecureChannel = $p.SignSecureChannel
                  $out.AvoidPdcOnWan = $p.AvoidPdcOnWan
                } catch { $out.Error = $_.Exception.Message }
                try { $out.PolicyDisablePasswordChange = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction Stop).DisablePasswordChange } catch { }
                try { $out.PolicyMaxPasswordAge = (Get-ItemProperty 'HKLM:\SOFTWARE\Policies\Microsoft\Windows\System' -ErrorAction Stop).MaximumPasswordAge } catch { }
                $out | ConvertTo-Json -Compress
                """;
            var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(60), cancellationToken);
            var json = ParseJsonObject(res.StdOut);
            var lines = new List<string>
            {
                "DisablePasswordChange: " + ValueText(json, "DisablePasswordChange"),
                "MaximumPasswordAge: " + ValueText(json, "MaximumPasswordAge") + " (дней, 0 = никогда)",
                "RequireSignOrSeal: " + ValueText(json, "RequireSignOrSeal"),
                "SealSecureChannel: " + ValueText(json, "SealSecureChannel"),
                "SignSecureChannel: " + ValueText(json, "SignSecureChannel"),
                "AvoidPdcOnWan: " + ValueText(json, "AvoidPdcOnWan"),
                "Policy\\DisablePasswordChange: " + ValueText(json, "PolicyDisablePasswordChange"),
                "Policy\\MaximumPasswordAge: " + ValueText(json, "PolicyMaxPasswordAge")
            };

            bool disabled = IsTrue(json, "DisablePasswordChange") || IsTrue(json, "PolicyDisablePasswordChange");
            bool never = ValueInt(json, "MaximumPasswordAge") == 0 || ValueInt(json, "PolicyMaxPasswordAge") == 0;
            string details = string.Join("\r\n", lines) +
                             (json == null ? "\r\nНе удалось прочитать ветку реестра Netlogon." : "");
            if (disabled)
                return new Outcome(CheckStatus.Warning,
                    "Смена пароля компьютера отключена политикой — доверие будет теряться со временем", details);
            if (never)
                return new Outcome(CheckStatus.Warning,
                    "Максимальный возраст пароля компьютера = 0 (пароль не меняется никогда)", details);
            return new Outcome(CheckStatus.Ok, "Политики смены пароля компьютера не мешают доверию", details);
        }, cancellationToken);

        // ---------- Protected Users ----------
        await AddAsync(report, "trust", "Доверие", "Учётная запись компьютера в группе Protected Users", async () =>
        {
            const string script = """
                $out = [ordered]@{}
                try {
                  $searcher = New-Object System.DirectoryServices.DirectorySearcher
                  $searcher.Filter = "(&(objectCategory=computer)(sAMAccountName=$($env:COMPUTERNAME)`$))"
                  [void]$searcher.PropertiesToLoad.Add('memberOf')
                  $r = $searcher.FindOne()
                  if ($null -eq $r) { $out.Found = $false }
                  else {
                    $out.Found = $true
                    $groups = @($r.Properties['memberOf'])
                    $out.Groups = $groups
                    $out.InProtectedUsers = [bool](@($groups | Where-Object { $_ -match 'CN=Protected Users' }).Count)
                  }
                } catch { $out.Error = $_.Exception.Message }
                $out | ConvertTo-Json -Depth 4 -Compress
                """;
            var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(60), cancellationToken);
            var json = ParseJsonObject(res.StdOut);
            if (json == null || (!string.IsNullOrEmpty(GetString(json.Value, "Error"))))
                return new Outcome(CheckStatus.Info, "Не удалось проверить членство в группе Protected Users",
                    res.Combined);
            if (!IsTrue(json.Value, "Found"))
                return new Outcome(CheckStatus.Info, "Учётная запись компьютера не найдена в AD (LDAP)",
                    res.Combined);
            if (IsTrue(json.Value, "InProtectedUsers"))
                return new Outcome(CheckStatus.Error,
                    "Компьютер входит в Protected Users — Windows не сохраняет его пароль, доверие будет теряться",
                    res.Combined);
            return new Outcome(CheckStatus.Ok, "Учётная запись компьютера не входит в Protected Users", res.Combined);
        }, cancellationToken);

        // ---------- dsregcmd ----------
        await AddAsync(report, "system", "Система", "Состояние устройства (dsregcmd /status)", async () =>
        {
            var res = await ProcessRunner.RunAsync(ProcessRunner.System32("dsregcmd.exe"), "/status",
                TimeSpan.FromSeconds(60), cancellationToken: cancellationToken);
            var values = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            foreach (var raw in res.Combined.Split('\n'))
            {
                var idx = raw.IndexOf(':');
                if (idx <= 0) continue;
                string key = raw[..idx].Trim();
                string value = raw[(idx + 1)..].Trim();
                if (key.Length > 0 && value.Length > 0 && !values.ContainsKey(key)) values[key] = value;
            }

            string details = res.Combined;
            if (values.Count == 0)
                return new Outcome(CheckStatus.Info, "Не удалось прочитать dsregcmd /status", details);

            string azure = values.TryGetValue("AzureAdJoined", out var a) ? a : "—";
            string domainJoined = values.TryGetValue("DomainJoined", out var d) ? d : "—";
            string provider = values.TryGetValue("KeyProvider", out var kp) ? kp : "—";
            string tpm = values.TryGetValue("TpmProtected", out var t) ? t : "—";
            string summary = $"AD: {domainJoined}, Azure AD: {azure}, ключ: {provider}, TPM: {tpm}";
            return new Outcome(CheckStatus.Info, summary, details);
        }, cancellationToken);

        // ---------- Event log ----------
        await AddAsync(report, "history", "Журналы", "Ошибки NETLOGON за 7 дней", async () =>
        {
            const string script = """
                $out = [ordered]@{}
                try {
                  $ev = @(Get-WinEvent -FilterHashtable @{ LogName = 'System'; ProviderName = 'NETLOGON'; StartTime = (Get-Date).AddDays(-7) } -ErrorAction Stop |
                        Sort-Object TimeCreated -Descending | Select-Object -First 10)
                  $out.Count = $ev.Count
                  $out.Items = @($ev | ForEach-Object {
                      [pscustomobject]@{
                        Time = $_.TimeCreated.ToString('yyyy-MM-dd HH:mm:ss')
                        Id = $_.Id
                        Level = $_.LevelDisplayName
                        Message = ($_.Message -replace "`r?`n", ' ')
                      }
                  })
                } catch { $out.Count = 0; $out.Items = @(); $out.Error = $_.Exception.Message }
                $out | ConvertTo-Json -Depth 5 -Compress
                """;
            var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(90), cancellationToken);
            var json = ParseJsonObject(res.StdOut);
            if (json == null)
                return new Outcome(CheckStatus.Info, "Не удалось прочитать журнал System", res.Combined);

            int count = ValueInt(json.Value, "Count");
            var lines = new List<string>();
            if (json.Value.ValueKind == JsonValueKind.Object &&
                json.Value.TryGetProperty("Items", out var items) && items.ValueKind == JsonValueKind.Array)
            {
                foreach (var item in items.EnumerateArray())
                {
                    lines.Add($"{GetString(item, "Time")}  [{GetString(item, "Id")}] {GetString(item, "Level")}: {GetString(item, "Message")}");
                }
            }

            string details = lines.Count > 0
                ? string.Join("\r\n", lines)
                : "События NETLOGON за 7 дней не найдены." +
                  (ValueText(json.Value, "Error") is { Length: > 0 } err ? "\r\n" + err : "");

            if (count == 0)
                return new Outcome(CheckStatus.Ok, "Ошибок NETLOGON за 7 дней нет", details);
            return new Outcome(CheckStatus.Warning, $"Событий NETLOGON за 7 дней: {count}", details);
        }, cancellationToken);

        BuildRecommendations(report, netbios);
        report.FinishedLocal = DateTime.Now;
        AppLog.Write($"=== Диагностика завершена: {report.OverallTitle} ===");
        return report;
    }

    // ------------------------------------------------------------------
    // Проверки, которые нужны и восстановлению
    // ------------------------------------------------------------------

    /// <summary>Проверяет защищённый канал. Возвращает (результат|null, метод, сообщение, подробности).</summary>
    public static async Task<(bool? Ok, string Method, string Message, string Raw)> TestSecureChannelAsync(
        string domain, CancellationToken cancellationToken = default)
    {
        const string script = """
            $out = [ordered]@{}
            try {
              $cmd = Get-Command Test-ComputerSecureChannel -ErrorAction Stop
              try {
                $r = Test-ComputerSecureChannel -ErrorAction Stop
                $out.Result = [bool]$r
              } catch {
                $out.Result = $false
                $out.Error = $_.Exception.Message
              }
            } catch {
              $out.Unavailable = $true
              $out.Error = $_.Exception.Message
            }
            $out | ConvertTo-Json -Compress
            """;
        var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(120), cancellationToken);
        var json = ParseJsonObject(res.StdOut);
        string raw = res.Combined;
        if (json is { ValueKind: JsonValueKind.Object })
        {
            var element = json.Value;
            if (!IsTrue(element, "Unavailable") && element.TryGetProperty("Result", out var result) &&
                (result.ValueKind == JsonValueKind.True || result.ValueKind == JsonValueKind.False))
            {
                bool ok = result.ValueKind == JsonValueKind.True;
                string message = GetString(element, "Error");
                return (ok, "Test-ComputerSecureChannel",
                    ok ? "Канал работает" : (message.Length > 0 ? message : "Проверка вернула False"), raw);
            }
        }

        // Резервный вариант — nltest /sc_query
        var nl = await ProcessRunner.RunAsync(ProcessRunner.System32("nltest.exe"), "/sc_query:" + domain,
            TimeSpan.FromSeconds(40), cancellationToken: cancellationToken);
        raw += "\r\n\r\n" + nl.Combined;
        if (nl.Success) return (true, "nltest /sc_query", "Канал работает", raw);
        if (nl.ExitCode == -1 && nl.TimedOut) return (null, "nltest /sc_query", "Таймаут", raw);
        string nlMessage = nl.FirstLine;
        return (false, "nltest /sc_query", string.IsNullOrEmpty(nlMessage) ? "Канал не работает" : nlMessage, raw);
    }

    /// <summary>Перепроверка доверия после восстановления.</summary>
    public static async Task<(bool? Ok, string Message)> VerifyTrustAsync(string domain,
        CancellationToken cancellationToken = default)
    {
        var (ok, method, message, _) = await TestSecureChannelAsync(domain, cancellationToken);
        if (ok == null) return (null, $"Не удалось проверить канал ({method}): {message}");
        if (ok == true) return (true, "Доверительные отношения восстановлены, защищённый канал работает.");
        return (false, "Защищённый канал по-прежнему не работает: " + message);
    }

    private static async Task<(bool Ok, List<string> Targets, string Error)> LookupDcRecordsAsync(
        string domain, CancellationToken cancellationToken)
    {
        var script = $$"""
            $out = [ordered]@{}
            try {
              $q = '_ldap._tcp.dc._msdcs.{{domain}}'
              $r = @(Resolve-DnsName -Name $q -Type SRV -ErrorAction Stop | Where-Object { $_.Type -eq 'SRV' })
              $out.Ok = ($r.Count -gt 0)
              $out.Targets = @($r | ForEach-Object { $_.NameTarget })
            } catch { $out.Ok = $false; $out.Error = $_.Exception.Message }
            $out | ConvertTo-Json -Compress
            """;
        var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(40), cancellationToken);
        var json = ParseJsonObject(res.StdOut);
        var targets = new List<string>();
        if (json is { ValueKind: JsonValueKind.Object })
        {
            if (json.Value.TryGetProperty("Targets", out var arr) && arr.ValueKind == JsonValueKind.Array)
                foreach (var t in arr.EnumerateArray())
                    if (t.ValueKind == JsonValueKind.String) targets.Add(t.GetString()!);
            return (IsTrue(json.Value, "Ok") && targets.Count > 0, targets, GetString(json.Value, "Error"));
        }

        return (false, targets, res.Combined);
    }

    private void BuildRecommendations(ScanReport report, string netbios)
    {
        if (report.SecureChannelOk == false)
        {
            if (report.DnsOk == false)
                report.Recommendations.Add(
                    "Исправьте DNS: клиент должен использовать DNS-серверы контроллеров домена, " +
                    "а зона домена должна разрешаться. Без этого доверие не восстановить.");
            if (report.TimeSkewOk == false)
                report.Recommendations.Add(
                    "Синхронизируйте время с контроллером (w32tm /resync /force). " +
                    "Расхождение более 5 минут ломает Kerberos.");
            if (report.DcReachable == false)
                report.Recommendations.Add(
                    "Проверьте сетевую доступность контроллера домена (порты 88, 389, 445, 135, 49152+).");
            report.Recommendations.Add(
                "Если сеть, DNS и время в порядке — выполните восстановление: программа сбросит пароль " +
                $"учётной записи {netbios}\\{report.ComputerName}$ и переустановит защищённый канал.");
        }
        else if (report.SecureChannelOk == true)
        {
            if (report.Checks.Any(c => c.Status == CheckStatus.Warning))
                report.Recommendations.Add("Доверие работает; устраните замечания, чтобы оно не нарушилось в будущем.");
            else
                report.Recommendations.Add("Восстановление не требуется.");
        }
        else
        {
            report.Recommendations.Add("Проверка канала не дала результата — проверьте сеть и права, затем запустите диагностику снова.");
        }

        if (report.KerberosOk == false)
            report.Recommendations.Add("Билет Kerberos не получен — после восстановления доверия очистите кэш (klist purge).");
    }

    // ------------------------------------------------------------------
    // Вспомогательные методы
    // ------------------------------------------------------------------

    private async Task AddAsync(ScanReport report, string category, string categoryTitle, string title,
        Func<Task<Outcome>> body, CancellationToken cancellationToken)
    {
        cancellationToken.ThrowIfCancellationRequested();
        ProgressChanged?.Invoke(title);
        AppLog.Write("Проверка: " + title);
        var sw = Stopwatch.StartNew();
        CheckResult result;
        try
        {
            var outcome = await body();
            result = new CheckResult
            {
                Id = title,
                Category = categoryTitle,
                Title = title,
                Summary = outcome.Summary,
                Details = outcome.Details,
                Status = outcome.Status
            };
        }
        catch (OperationCanceledException)
        {
            throw;
        }
        catch (Exception ex)
        {
            result = new CheckResult
            {
                Id = title,
                Category = categoryTitle,
                Title = title,
                Summary = "Проверка завершилась ошибкой: " + ex.Message,
                Details = ex.ToString(),
                Status = CheckStatus.Warning
            };
            AppLog.Write("Ошибка проверки «" + title + "»: " + ex.Message);
        }

        result.Duration = sw.Elapsed;
        report.Checks.Add(result);
        CheckCompleted?.Invoke(result);
    }

    private static string DescribeJoinStatus(NetJoinStatus status) => status switch
    {
        NetJoinStatus.NetSetupDomainName => "Компьютер в домене",
        NetJoinStatus.NetSetupWorkgroupName => "Компьютер в рабочей группе",
        NetJoinStatus.NetSetupUnjoined => "Компьютер не присоединён",
        _ => "Неизвестно"
    };

    private static double? ParseStripchartOffset(string output)
    {
        var matches = Regex.Matches(output, @"([+-]\s*\d+(?:[.,]\d+)?)\s*s");
        if (matches.Count == 0) return null;
        string value = matches[^1].Groups[1].Value.Replace(" ", "").Replace(',', '.');
        return double.TryParse(value, System.Globalization.NumberStyles.Float,
            System.Globalization.CultureInfo.InvariantCulture, out double result)
            ? result
            : null;
    }

    private static List<JsonElement> ParseJsonArray(string stdout, string fallback)
    {
        foreach (var text in new[] { stdout, fallback })
        {
            string trimmed = text.Trim();
            if (!trimmed.StartsWith("[") && !trimmed.StartsWith("{")) continue;
            try
            {
                using var doc = JsonDocument.Parse(trimmed);
                if (doc.RootElement.ValueKind == JsonValueKind.Array)
                    return doc.RootElement.EnumerateArray().Select(e => e.Clone()).ToList();
                if (doc.RootElement.ValueKind == JsonValueKind.Object)
                    return new List<JsonElement> { doc.RootElement.Clone() };
            }
            catch
            {
                // пробуем следующий вариант
            }
        }

        return new List<JsonElement>();
    }

    private static JsonElement? ParseJsonObject(string stdout)
    {
        string trimmed = stdout.Trim();
        int start = trimmed.IndexOf('{');
        int end = trimmed.LastIndexOf('}');
        if (start < 0 || end <= start) return null;
        try
        {
            using var doc = JsonDocument.Parse(trimmed[start..(end + 1)]);
            if (doc.RootElement.ValueKind != JsonValueKind.Object) return null;
            return doc.RootElement.Clone();
        }
        catch
        {
            return null;
        }
    }

    private static string GetString(JsonElement element, string name)
    {
        if (element.ValueKind != JsonValueKind.Object) return "";
        if (!element.TryGetProperty(name, out var value)) return "";
        return value.ValueKind switch
        {
            JsonValueKind.String => value.GetString() ?? "",
            JsonValueKind.True => "True",
            JsonValueKind.False => "False",
            JsonValueKind.Null => "",
            _ => value.ToString()
        };
    }

    private static string ValueText(JsonElement? element, string name)
    {
        if (element == null) return "—";
        if (element.Value.ValueKind != JsonValueKind.Object) return "—";
        if (!element.Value.TryGetProperty(name, out var value) || value.ValueKind == JsonValueKind.Null) return "—";
        return value.ToString();
    }

    private static int ValueInt(JsonElement? element, string name)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Object) return -1;
        if (!element.Value.TryGetProperty(name, out var value)) return -1;
        return value.ValueKind switch
        {
            JsonValueKind.Number => value.TryGetInt32(out int i) ? i : -1,
            JsonValueKind.String => int.TryParse(value.GetString(), out int i) ? i : -1,
            _ => -1
        };
    }

    private static bool IsTrue(JsonElement? element, string name)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Object) return false;
        if (!element.Value.TryGetProperty(name, out var value)) return false;
        return value.ValueKind switch
        {
            JsonValueKind.True => true,
            JsonValueKind.Number => value.TryGetInt32(out int i) && i == 1,
            JsonValueKind.String => value.GetString() is "True" or "true" or "1",
            _ => false
        };
    }
}
