using System.Diagnostics;
using System.Text.Json;
using AdTrustRepair.Models;
using AdTrustRepair.Native;

namespace AdTrustRepair.Services;

/// <summary>Восстановление доверительных отношений компьютера с доменом.</summary>
public sealed class RepairService
{
    public event Action<RepairStepResult>? StepCompleted;
    public event Action<string>? ProgressChanged;

    private RepairReport _report = new();
    private RepairOptions _options = new();
    private string _domain = "";
    private string _netbios = "";
    private string _computerAccount = "";
    private string? _dc;

    private sealed record ResetAttempt(ResetMethod Method, bool Success, bool Skipped, string Message, string? Password);

    public async Task<RepairReport> RepairAsync(ScanReport scan, RepairOptions options,
        CancellationToken cancellationToken = default)
    {
        _report = new RepairReport { StartedLocal = DateTime.Now };
        _options = options;
        _domain = scan.DomainName;
        _netbios = !string.IsNullOrWhiteSpace(scan.NetBiosDomain)
            ? scan.NetBiosDomain
            : MachineInfo.NormalizeDomainName(scan.DomainName);
        _computerAccount = (string.IsNullOrWhiteSpace(scan.ComputerName)
            ? MachineInfo.GetIdentity().NetBiosName
            : scan.ComputerName) + "$";
        _dc = scan.DomainController;

        AppLog.Write("=== Запуск восстановления ===");

        if (!scan.IsDomainJoined || string.IsNullOrWhiteSpace(_domain))
        {
            return Fail("Компьютер не входит в домен — восстанавливать доверие не требуется. " +
                        "При необходимости присоедините компьютер к домену.");
        }

        if (!Program.IsElevated())
            return Fail("Требуются права администратора. Перезапустите программу от имени администратора.");

        AddStep("Исходное состояние",
            true,
            false,
            scan.TrustBroken
                ? $"Доверие нарушено. Домен: {_domain}, компьютер: {_computerAccount}"
                : $"Проверка канала до восстановления: {(scan.SecureChannelOk == true ? "канал работает" : "состояние неизвестно")}. " +
                  "Восстановление выполнено по запросу оператора.");

        if (options.PurgeKerberosTickets)
        {
            var purge = await ProcessRunner.RunAsync(ProcessRunner.System32("klist.exe"), "purge",
                TimeSpan.FromSeconds(30), logCommand: false, cancellationToken: cancellationToken);
            AddStep("Очистка кэша Kerberos (klist purge)", purge.Success || purge.Combined.Contains("0"),
                false, purge.Success ? "Кэш билетов очищен." : "Не удалось очистить кэш: " + purge.FirstLine);
        }

        if (options.FlushDns)
        {
            var flush = await ProcessRunner.RunAsync(ProcessRunner.System32("ipconfig.exe"), "/flushdns",
                TimeSpan.FromSeconds(30), cancellationToken: cancellationToken);
            AddStep("Сброс кэша DNS (ipconfig /flushdns)", flush.Success, false,
                flush.Success ? "Кэш DNS сброшен." : "Не удалось сбросить кэш DNS: " + flush.FirstLine);
        }

        if (options.ResetMachinePassword)
        {
            ProgressChanged?.Invoke("Сброс пароля учётной записи компьютера");
            bool reset = await ResetMachinePasswordAsync(cancellationToken);
            if (!reset)
            {
                _report.ErrorMessage = "Не удалось сбросить пароль учётной записи компьютера ни одним из способов. " +
                                       "См. подробности шагов выше.";
                _report.FinishedLocal = DateTime.Now;
                return _report;
            }
        }
        else
        {
            AddStep("Сброс пароля компьютера", false, true,
                "Отключён в настройках — выполняется только восстановление канала.");
            if (options.AllowFallbackMethods)
            {
                ProgressChanged?.Invoke("Восстановление защищённого канала");
                var scp = await TrySecureChannelRepairAsync(cancellationToken);
                AddStep("Восстановление канала (Test-ComputerSecureChannel -Repair)", scp.Success, scp.Skipped,
                    scp.Message);
                if (scp.Success) _report.MethodUsed = DescribeMethod(ResetMethod.SecureChannelRepair);
            }
        }

        // После смены пароля очищаем старые билеты и перезапускаем Netlogon,
        // чтобы LSA/Netlogon перечитали секрет.
        if (options.PurgeKerberosTickets)
        {
            await ProcessRunner.RunAsync(ProcessRunner.System32("klist.exe"), "purge",
                TimeSpan.FromSeconds(30), logCommand: false, cancellationToken: cancellationToken);
        }

        if (options.RestartNetlogon)
        {
            ProgressChanged?.Invoke("Перезапуск службы Netlogon");
            const string script = """
                $out = [ordered]@{}
                try {
                  Restart-Service -Name Netlogon -Force -ErrorAction Stop
                  $out.Ok = $true
                } catch { $out.Ok = $false; $out.Error = $_.Exception.Message }
                Start-Sleep -Seconds 2
                try { $out.Status = (Get-Service Netlogon).Status.ToString() } catch { }
                $out | ConvertTo-Json -Compress
                """;
            var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(90), cancellationToken);
            bool ok = res.StdOut.Contains("\"Ok\":true") || res.StdOut.Contains("\"Ok\": true");
            AddStep("Перезапуск службы Netlogon", ok, false,
                ok ? "Служба Netlogon перезапущена, секрет перечитан." :
                "Не удалось перезапустить Netlogon: " + res.FirstLine);
        }

        // nltest /sc_verify + /sc_reset — установка защищённого канала с новым паролем
        await EstablishSecureChannelAsync(cancellationToken);

        if (options.ForceGroupPolicy)
        {
            ProgressChanged?.Invoke("Обновление групповых политик");
            var gp = await ProcessRunner.RunAsync(ProcessRunner.System32("gpupdate.exe"), "/force",
                TimeSpan.FromMinutes(5), cancellationToken: cancellationToken);
            AddStep("Обновление групповых политик (gpupdate /force)", gp.Success, false,
                gp.Success ? "Политики обновлены." : "gpupdate завершился с ошибкой: " + gp.FirstLine);
        }

        if (options.VerifyAfterRepair)
        {
            ProgressChanged?.Invoke("Проверка результата");
            var (ok, message) = await DiagnosticsService.VerifyTrustAsync(_domain, cancellationToken);
            _report.TrustRestored = ok;
            _report.VerificationMessage = message;

            string realm = _domain.ToUpperInvariant();
            var krb = await ProcessRunner.RunAsync(ProcessRunner.System32("klist.exe"), $"get krbtgt/{realm}",
                TimeSpan.FromSeconds(30), logCommand: false, cancellationToken: cancellationToken);
            AddStep("Проверка защищённого канала", ok == true, ok == null, message);
            AddStep("Получение Kerberos-билета", krb.Success, false,
                krb.Success ? $"Билет krbtgt/{realm} успешно получен." : "Билет не получен: " + krb.FirstLine);
        }

        _report.FinishedLocal = DateTime.Now;
        AppLog.Write(_report.TrustRestored == true
            ? "=== Восстановление завершено успешно ==="
            : "=== Восстановление завершено, доверие не подтверждено ===");
        return _report;
    }

    // ------------------------------------------------------------------

    private async Task<bool> ResetMachinePasswordAsync(CancellationToken cancellationToken)
    {
        var order = new List<ResetMethod> { _options.PreferredMethod };
        if (_options.AllowFallbackMethods)
        {
            foreach (var method in new[]
                     {
                         ResetMethod.ResetComputerMachinePassword, ResetMethod.SecureChannelRepair,
                         ResetMethod.Netdom, ResetMethod.LsaNetUser
                     })
            {
                if (!order.Contains(method)) order.Add(method);
            }
        }

        var failures = new List<string>();
        foreach (var method in order)
        {
            cancellationToken.ThrowIfCancellationRequested();
            ProgressChanged?.Invoke("Сброс пароля компьютера: " + DescribeMethod(method));
            var result = method switch
            {
                ResetMethod.ResetComputerMachinePassword => await TryResetComputerMachinePasswordAsync(cancellationToken),
                ResetMethod.LsaNetUser => await TryLsaMethodAsync(cancellationToken),
                ResetMethod.Netdom => await TryNetdomAsync(cancellationToken),
                ResetMethod.Ksetup => await TryKsetupAsync(cancellationToken),
                ResetMethod.SecureChannelRepair => await TrySecureChannelRepairAsync(cancellationToken),
                _ => new ResetAttempt(method, false, true, "Неизвестный способ.", null)
            };

            AddStep("Сброс пароля компьютера: " + DescribeMethod(method), result.Success, result.Skipped,
                result.Message);

            if (result.Success)
            {
                _report.MachinePasswordReset = true;
                _report.MethodUsed = DescribeMethod(method);
                _report.NewPassword = result.Password;
                return true;
            }

            if (!result.Skipped) failures.Add(DescribeMethod(method) + ": " + result.Message);
            if (!_options.AllowFallbackMethods) break;
        }

        // последняя попытка — «мягкое» восстановление канала средствами Windows
        if (_options.AllowFallbackMethods && !order.Contains(ResetMethod.SecureChannelRepair))
        {
            var scp = await TrySecureChannelRepairAsync(cancellationToken);
            AddStep("Восстановление канала (Test-ComputerSecureChannel -Repair)", scp.Success, scp.Skipped, scp.Message);
            if (scp.Success)
            {
                _report.MethodUsed = DescribeMethod(ResetMethod.SecureChannelRepair);
                _report.NewPassword = scp.Password;
                return true;
            }
        }

        if (failures.Count > 0)
            AppLog.Write("Все способы сброса пароля завершились ошибкой: " + string.Join(" | ", failures));
        return false;
    }

    /// <summary>
    /// Штатный способ Windows: Reset-ComputerMachinePassword меняет пароль учётной записи
    /// компьютера в AD и синхронно обновляет локальный секрет.
    /// </summary>
    private async Task<ResetAttempt> TryResetComputerMachinePasswordAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.DomainAdminUser) ||
            string.IsNullOrWhiteSpace(_options.DomainAdminPassword))
        {
            return new ResetAttempt(ResetMethod.ResetComputerMachinePassword, false, true,
                "Не указаны учётные данные администратора домена. Этот способ работает от учётной записи, " +
                "у которой есть права на сброс пароля компьютера (Domain Admins или делегированные права).", null);
        }

        const string script = """
            $out = [ordered]@{}
            try {
              $sec = ConvertTo-SecureString $env:ATR_ADMIN_PASS -AsPlainText -Force
              $p = New-Object System.Management.Automation.PSCredential($env:ATR_ADMIN_USER, $sec)
              $params = @{ Credential = $p }
              if ($env:ATR_DC) { $params['Server'] = $env:ATR_DC }
              Reset-ComputerMachinePassword @params -ErrorAction Stop
              $out.Ok = $true
            } catch {
              $out.Ok = $false
              $out.Error = $_.Exception.Message
            }
            Start-Sleep -Seconds 2
            try { $out.Secure = [bool](Test-ComputerSecureChannel -ErrorAction Stop) } catch { $out.Secure = $false }
            $out | ConvertTo-Json -Compress
            """;

        var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(180), cancellationToken,
            BuildCredentialEnvironment());
        var json = ParseJson(res.StdOut);
        bool ok = JsonTrue(json, "Ok");
        string error = JsonString(json, "Error");
        bool secure = JsonTrue(json, "Secure");

        if (!ok)
        {
            return new ResetAttempt(ResetMethod.ResetComputerMachinePassword, false, false,
                "Reset-ComputerMachinePassword не удался" + (error.Length > 0 ? ": " + error : ".") +
                " Проверьте права учётной записи, доступность контроллера и наличие открытых SMB-сеансов к DC.", null);
        }

        return new ResetAttempt(ResetMethod.ResetComputerMachinePassword, true, false,
            secure
                ? "Пароль компьютера сброшен, защищённый канал работает."
                : "Пароль компьютера сброшен, но проверка канала ещё не прошла. " +
                  "Продолжаем: перезапуск Netlogon и nltest /sc_reset.", null);
    }

    private Dictionary<string, string> BuildCredentialEnvironment()
    {
        var env = new Dictionary<string, string> { ["ATR_DC"] = _dc ?? "" };
        if (!string.IsNullOrWhiteSpace(_options.DomainAdminUser) &&
            !string.IsNullOrWhiteSpace(_options.DomainAdminPassword))
        {
            string admin = _options.DomainAdminUser!;
            if (!admin.Contains('\\') && !admin.Contains('@'))
                admin = _netbios + "\\" + admin;
            env["ATR_ADMIN_USER"] = admin;
            env["ATR_ADMIN_PASS"] = _options.DomainAdminPassword!;
        }

        return env;
    }

    private static JsonElement? ParseJson(string stdout)
    {
        string text = stdout.Trim();
        int start = text.IndexOf('{');
        int end = text.LastIndexOf('}');
        if (start < 0 || end <= start) return null;
        try
        {
            using var doc = JsonDocument.Parse(text[start..(end + 1)]);
            return doc.RootElement.ValueKind == JsonValueKind.Object ? doc.RootElement.Clone() : null;
        }
        catch
        {
            return null;
        }
    }

    private static bool JsonTrue(JsonElement? element, string name)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Object) return false;
        return element.Value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.True;
    }

    private static string JsonString(JsonElement? element, string name)
    {
        if (element == null || element.Value.ValueKind != JsonValueKind.Object) return "";
        return element.Value.TryGetProperty(name, out var property) && property.ValueKind == JsonValueKind.String
            ? property.GetString() ?? ""
            : "";
    }

    /// <summary>
    /// Основной способ: читаем сохранённый пароль компьютера из секрета LSA,
    /// задаём новой учётной записи новый пароль и записываем секрет заново.
    /// </summary>
    private async Task<ResetAttempt> TryLsaMethodAsync(CancellationToken cancellationToken)
    {
        return await Task.Run(() =>
        {
            string user;
            byte[] originalBlob;
            string originalDecrypted;
            try
            {
                using var system = Impersonation.AsSystem();
                AppLog.Write("Чтение секрета LSA " + LsaSecret.MachineAccountSecretPath);
                originalBlob = LsaSecret.Read(LsaSecret.MachineAccountSecretPath);
                if (originalBlob.Length == 0)
                    return new ResetAttempt(ResetMethod.LsaNetUser, false, false,
                        "Секрет $MACHINE.ACC пуст — сохранить исходные учётные данные нельзя.", null);

                originalDecrypted = Dpapi.UnprotectToText(originalBlob);
            }
            catch (Exception ex)
            {
                return new ResetAttempt(ResetMethod.LsaNetUser, false, false,
                    "Не удалось прочитать/расшифровать секрет $MACHINE.ACC: " + ex.Message, null);
            }

            var parsed = LsaSecret.ParseSecret(originalDecrypted);
            user = parsed?.User ?? $"{_netbios}\\{_computerAccount}";
            AppLog.Write("Учётная запись компьютера в секрете: " + user);
            BackupSecret(originalBlob);

            string password = PasswordGenerator.Generate();
            bool passwordSet = false;
            string? lastError = null;

            // 1) от имени администратора
            try
            {
                NetUser.SetPassword(_computerAccount, password);
                passwordSet = true;
                AppLog.Write("Пароль учётной записи задан через NetUserSetInfo (администратор).");
            }
            catch (Exception ex)
            {
                lastError = ex.Message;
                AppLog.Write("NetUserSetInfo от администратора не удался: " + ex.Message);
            }

            // 2) от имени SYSTEM
            if (!passwordSet)
            {
                try
                {
                    using var system = Impersonation.AsSystem();
                    NetUser.SetPassword(_computerAccount, password);
                    passwordSet = true;
                    AppLog.Write("Пароль учётной записи задан через NetUserSetInfo (SYSTEM).");
                }
                catch (Exception ex)
                {
                    lastError = ex.Message;
                    AppLog.Write("NetUserSetInfo от SYSTEM не удался: " + ex.Message);
                }
            }

            if (!passwordSet)
            {
                return new ResetAttempt(ResetMethod.LsaNetUser, false, false,
                    "Не удалось задать новый пароль в AD: " + lastError +
                    " Используйте способ netdom с учётными данными администратора домена.", null);
            }

            try
            {
                using var system = Impersonation.AsSystem();
                // Windows хранит содержимое секрета зашифрованным через DPAPI
                // в контексте машины, поэтому пишем такой же блоб, а не открытый текст.
                var protectedBlob = Dpapi.Protect(LsaSecret.BuildSecretBlob(user, password));
                LsaSecret.Write(LsaSecret.MachineAccountSecretPath, protectedBlob);
                LsaSecret.Write(LsaSecret.SecretsMachineAccountPath, protectedBlob);
                AppLog.Write("Секреты LSA обновлены: $MACHINE.ACC и SECRETS\\MACHINE.ACC");

                // проверка чтением
                byte[] check = LsaSecret.Read(LsaSecret.MachineAccountSecretPath);
                string checkText = Dpapi.UnprotectToText(check);
                var checkParsed = LsaSecret.ParseSecret(checkText);
                if (checkParsed == null || checkParsed.Value.Password != password)
                    return new ResetAttempt(ResetMethod.LsaNetUser, false, false,
                        "Секрет записан, но проверка чтением не совпала. Требуется netdom resetpwd.", null);
            }
            catch (Exception ex)
            {
                return new ResetAttempt(ResetMethod.LsaNetUser, false, false,
                    "Пароль в AD изменён, но записать секрет LSA не удалось: " + ex.Message +
                    " Перезапустите Netlogon и/или используйте netdom resetpwd.", null);
            }

            return new ResetAttempt(ResetMethod.LsaNetUser, true, false,
                "Пароль компьютера сброшен локально, секреты LSA обновлены и проверены чтением.", password);
        }, cancellationToken);
    }

    private async Task<ResetAttempt> TryNetdomAsync(CancellationToken cancellationToken)
    {
        if (string.IsNullOrWhiteSpace(_options.DomainAdminUser) ||
            string.IsNullOrWhiteSpace(_options.DomainAdminPassword))
        {
            return new ResetAttempt(ResetMethod.Netdom, false, true,
                "Не указаны учётные данные администратора домена (нужны для netdom resetpwd).", null);
        }

        string admin = _options.DomainAdminUser!.Contains('\\') || _options.DomainAdminUser.Contains('@')
            ? _options.DomainAdminUser
            : _netbios + "\\" + _options.DomainAdminUser;

        string args = "resetpwd /userd:" + Quote(admin) + " /passwordd:*";
        if (!string.IsNullOrWhiteSpace(_dc)) args += " /server:" + Quote(_dc);

        var res = await ProcessRunner.RunAsync(ProcessRunner.System32("netdom.exe"), args,
            TimeSpan.FromSeconds(120), stdin: _options.DomainAdminPassword, cancellationToken: cancellationToken);

        bool ok = res.Success;
        return new ResetAttempt(ResetMethod.Netdom, ok, false,
            ok
                ? "netdom resetpwd успешно сбросил пароль компьютера и восстановил канал."
                : "netdom resetpwd завершился ошибкой: " + (res.Combined.Length > 0 ? res.Combined : "код " + res.ExitCode),
            null);
    }

    private async Task<ResetAttempt> TryKsetupAsync(CancellationToken cancellationToken)
    {
        if (_options.DsregLeaveBeforeKsetup)
        {
            var leave = await ProcessRunner.RunAsync(ProcessRunner.System32("dsregcmd.exe"), "/leave",
                TimeSpan.FromSeconds(60), cancellationToken: cancellationToken);
            AppLog.Write("dsregcmd /leave: " + (leave.Success ? "выполнено" : leave.FirstLine));
        }

        string password = PasswordGenerator.Generate();
        var res = await ProcessRunner.RunAsync(ProcessRunner.System32("ksetup.exe"),
            "/setcomputerpassword " + Quote(password), TimeSpan.FromSeconds(60),
            logCommand: false, cancellationToken: cancellationToken);
        AppLog.Write("ksetup /setcomputerpassword: код " + res.ExitCode);

        if (res.Success)
        {
            return new ResetAttempt(ResetMethod.Ksetup, true, false,
                "Пароль изменён через ksetup /setcomputerpassword. Внимание: этот способ может " +
                "нарушить ключ устройства (TPM/Intune) — при необходимости выполните повторную регистрацию.", password);
        }

        return new ResetAttempt(ResetMethod.Ksetup, false, false,
            "ksetup не смог изменить пароль: " + (res.Combined.Length > 0 ? res.Combined : "код " + res.ExitCode),
            null);
    }

    private async Task<ResetAttempt> TrySecureChannelRepairAsync(CancellationToken cancellationToken)
    {
        const string script = """
            $out = [ordered]@{}
            try {
              $p = $null
              if ($env:ATR_ADMIN_USER) {
                $sec = ConvertTo-SecureString $env:ATR_ADMIN_PASS -AsPlainText -Force
                $p = New-Object System.Management.Automation.PSCredential($env:ATR_ADMIN_USER, $sec)
              }
              if ($p) { $r = Test-ComputerSecureChannel -Repair -Credential $p -ErrorAction Stop }
              else { $r = Test-ComputerSecureChannel -Repair -ErrorAction Stop }
              $out.Result = [bool]$r
            } catch {
              $out.Result = $false
              $out.Error = $_.Exception.Message
            }
            $out | ConvertTo-Json -Compress
            """;

        var res = await ProcessRunner.PowerShellAsync(script, TimeSpan.FromSeconds(180), cancellationToken,
            BuildCredentialEnvironment());
        var json = ParseJson(res.StdOut);
        bool ok = JsonTrue(json, "Result");
        string error = JsonString(json, "Error");

        return new ResetAttempt(ResetMethod.SecureChannelRepair, ok, false,
            ok
                ? "Test-ComputerSecureChannel -Repair сообщил об успешном восстановлении канала."
                : "Test-ComputerSecureChannel -Repair не удался" + (error.Length > 0 ? ": " + error : "."),
            null);
    }

    private async Task EstablishSecureChannelAsync(CancellationToken cancellationToken)
    {
        var verify = await ProcessRunner.RunAsync(ProcessRunner.System32("nltest.exe"), "/sc_verify:" + _domain,
            TimeSpan.FromSeconds(40), cancellationToken: cancellationToken);
        if (verify.Success)
        {
            AddStep("Проверка канала (nltest /sc_verify)", true, false, "Защищённый канал установлен.");
            return;
        }

        AppLog.Write("nltest /sc_verify не удался: " + verify.Combined);
        var reset = await ProcessRunner.RunAsync(ProcessRunner.System32("nltest.exe"), "/sc_reset:" + _domain,
            TimeSpan.FromSeconds(40), cancellationToken: cancellationToken);
        AddStep("Установка канала (nltest /sc_reset)", reset.Success, false,
            reset.Success
                ? "Канал переустановлен по локальным учётным данным компьютера."
                : "nltest /sc_reset не удался: " + (reset.Combined.Length > 0 ? reset.Combined : "код " + reset.ExitCode));
    }

    // ------------------------------------------------------------------

    private static void BackupSecret(byte[] blob)
    {
        try
        {
            string dir = Path.Combine(
                Environment.GetFolderPath(Environment.SpecialFolder.CommonApplicationData),
                "AdTrustRepair", "Backups");
            Directory.CreateDirectory(dir);
            string file = Path.Combine(dir, $"MACHINE.ACC.{DateTime.Now:yyyyMMdd-HHmmss}.bin");
            File.WriteAllBytes(file, blob);
            AppLog.Write("Резервная копия исходного секрета: " + file);
        }
        catch (Exception ex)
        {
            AppLog.Write("Не удалось сохранить резервную копию секрета: " + ex.Message);
        }
    }

    private static string Quote(string value) => "\"" + value.Replace("\"", "\\\"") + "\"";

    private static string DescribeMethod(ResetMethod method) => method switch
    {
        ResetMethod.ResetComputerMachinePassword => "Reset-ComputerMachinePassword",
        ResetMethod.LsaNetUser => "локальный (LSA + NetUserSetInfo)",
        ResetMethod.Netdom => "netdom resetpwd",
        ResetMethod.Ksetup => "ksetup",
        ResetMethod.SecureChannelRepair => "Test-ComputerSecureChannel -Repair",
        _ => method.ToString()
    };

    private void AddStep(string title, bool success, bool skipped, string message)
    {
        var step = new RepairStepResult
        {
            Title = title,
            Success = success,
            Skipped = skipped,
            Message = message
        };
        _report.Steps.Add(step);
        string prefix = skipped ? "[пропуск] " : success ? "[успех] " : "[ошибка] ";
        AppLog.Write(prefix + title + " — " + message);
        StepCompleted?.Invoke(step);
    }

    private RepairReport Fail(string message)
    {
        _report.ErrorMessage = message;
        _report.FinishedLocal = DateTime.Now;
        AddStep("Восстановление невозможно", false, false, message);
        return _report;
    }
}
