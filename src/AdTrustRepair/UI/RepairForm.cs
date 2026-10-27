using AdTrustRepair.Models;
using AdTrustRepair.Services;

namespace AdTrustRepair.UI;

/// <summary>Диалог восстановления доверия: параметры, ход выполнения и результат.</summary>
public sealed class RepairForm : Form
{
    private readonly ScanReport _scan;
    private readonly RepairService _repair = new();

    private readonly RadioButton _rbRcmp = new();
    private readonly RadioButton _rbScp = new();
    private readonly RadioButton _rbNetdom = new();
    private readonly RadioButton _rbLsa = new();
    private readonly RadioButton _rbKsetup = new();
    private readonly CheckBox _cbFallback = new();
    private readonly CheckBox _cbResetPassword = new();
    private readonly CheckBox _cbPurgeKerberos = new();
    private readonly CheckBox _cbFlushDns = new();
    private readonly CheckBox _cbRestartNetlogon = new();
    private readonly CheckBox _cbGpupdate = new();
    private readonly CheckBox _cbVerify = new();
    private readonly TextBox _tbAdminUser = new();
    private readonly TextBox _tbAdminPassword = new();
    private readonly Panel _optionsPanel = new();
    private readonly RichTextBox _resultBox = new();
    private readonly Label _statusLabel = new();
    private readonly Button _btnPrimary = Theme.MakePrimaryButton("Восстановить доверие");
    private readonly Button _btnSecondary = Theme.MakeSecondaryButton("Отмена", 130);
    private readonly Panel _passwordPanel = new();
    private readonly TextBox _tbPassword = new();
    private readonly CheckBox _cbShowPassword = new();

    private CancellationTokenSource? _cts;
    private bool _running;
    private bool _finished;

    public RepairReport? Report { get; private set; }

    public RepairForm(ScanReport scan)
    {
        _scan = scan;

        Text = "Восстановление доверия к домену";
        Font = Theme.FontBase;
        BackColor = Theme.Bg;
        StartPosition = FormStartPosition.CenterParent;
        ClientSize = new Size(880, 940);
        MinimumSize = new Size(820, 780);
        ShowInTaskbar = false;

        BuildLayout();
        WireEvents();
        UpdatePrimaryState();
    }

    private void BuildLayout()
    {
        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 4,
            BackColor = Theme.Bg,
            Padding = new Padding(16)
        };
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 84));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 466));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Absolute, 78));

        root.Controls.Add(BuildHeader(), 0, 0);
        root.Controls.Add(BuildOptions(), 0, 1);
        root.Controls.Add(BuildResults(), 0, 2);
        root.Controls.Add(BuildFooter(), 0, 3);
        Controls.Add(root);
    }

    private Control BuildHeader()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        panel.Paint += (_, e) =>
        {
            var g = e.Graphics;
            g.Clear(Theme.Bg);
            var card = new Rectangle(0, 0, panel.Width - 1, panel.Height - 8);
            Theme.FillRounded(g, card, 12, Color.White);
            Theme.DrawRoundedBorder(g, card, 12, Theme.Border);

            var icon = new Rectangle(16, 16, 40, 40);
            Theme.FillRounded(g, icon, 20, Theme.WarnBg);
            TextRenderer.DrawText(g, "!", Theme.FontGlyphWarning, icon, Theme.Warn,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

            TextRenderer.DrawText(g, "Восстановление доверия к домену", Theme.FontH2,
                new Rectangle(68, 14, panel.Width - 90, 26), Theme.Text,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
            TextRenderer.DrawText(g,
                $"Компьютер {_scan.ComputerName} • домен {_scan.DomainName} • " +
                (_scan.TrustBroken ? "доверие нарушено" : "доверие сейчас работает") +
                (_scan.DomainController is { Length: > 0 } dc ? $" • контроллер {dc}" : ""),
                Theme.FontSmall, new Rectangle(69, 40, panel.Width - 90, 24), Theme.TextMuted,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        };
        return panel;
    }

    private Control BuildOptions()
    {
        _optionsPanel.Dock = DockStyle.Fill;
        _optionsPanel.AutoScroll = true;
        _optionsPanel.BackColor = Theme.Bg;
        _optionsPanel.Padding = new Padding(0, 0, 0, 8);
        _optionsPanel.Paint += (_, e) =>
        {
            var g = e.Graphics;
            var card = new Rectangle(0, 0, _optionsPanel.Width - 1, _optionsPanel.Height - 9);
            Theme.FillRounded(g, card, 12, Color.White);
            Theme.DrawRoundedBorder(g, card, 12, Theme.Border);
        };

        var inner = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = true,
            BackColor = Color.White,
            Padding = new Padding(18, 14, 18, 12)
        };

        inner.Controls.Add(SectionTitle("Способ восстановления"));

        AddOption(inner, _rbRcmp, "Reset-ComputerMachinePassword — рекомендуется",
            "Штатный способ Windows: новый пароль компьютера записывается в AD и в локальный секрет. " +
            "Требует учётные данные администратора домена (или входа под доменной учётной записью с нужными правами).");

        AddOption(inner, _rbScp, "Test-ComputerSecureChannel -Repair — штатное восстановление канала",
            "Переустанавливает защищённый канал; с указанными учётными данными может сбросить пароль компьютера.");

        AddOption(inner, _rbNetdom, "netdom resetpwd — нужны права администратора домена",
            "Классическая утилита: пароль сбрасывается локально и в AD. Может не сработать при открытых SMB-сеансах к контроллеру.");

        AddOption(inner, _rbLsa, "Экспертный: локальный сброс через LSA + NetUserSetInfo",
            "Читает секрет $MACHINE.ACC, меняет пароль учётной записи компьютера и перезаписывает секреты LSA. " +
            "Учётные данные администратора домена не нужны, но способ работает только при наличии прав на сброс пароля компьютера.");

        AddOption(inner, _rbKsetup, "ksetup /setcomputerpassword — резервный",
            "Меняет пароль через ksetup; может нарушить ключ устройства (TPM/Intune), поэтому используется последним.");

        _cbFallback.Text = "Если выбранный способ не сработал — попробовать остальные";
        _cbFallback.Checked = true;
        _cbFallback.AutoSize = true;
        _cbFallback.Margin = new Padding(0, 4, 0, 10);
        inner.Controls.Add(_cbFallback);

        inner.Controls.Add(SectionTitle("Учётные данные администратора домена"));

        var credentials = new TableLayoutPanel
        {
            Width = 660,
            Height = 64,
            ColumnCount = 2,
            RowCount = 2,
            Margin = new Padding(0, 0, 0, 4)
        };
        credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 120));
        credentials.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        credentials.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        credentials.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

        credentials.Controls.Add(new Label
        {
            Text = "Пользователь",
            TextAlign = ContentAlignment.MiddleLeft,
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextMuted
        }, 0, 0);
        _tbAdminUser.Dock = DockStyle.Fill;
        _tbAdminUser.PlaceholderText = @"CORP\admin или admin@corp.example.com";
        credentials.Controls.Add(_tbAdminUser, 1, 0);

        credentials.Controls.Add(new Label
        {
            Text = "Пароль",
            TextAlign = ContentAlignment.MiddleLeft,
            Dock = DockStyle.Fill,
            ForeColor = Theme.TextMuted
        }, 0, 1);
        _tbAdminPassword.Dock = DockStyle.Fill;
        _tbAdminPassword.UseSystemPasswordChar = true;
        _tbAdminPassword.PlaceholderText = "Не сохраняется на диск";
        credentials.Controls.Add(_tbAdminPassword, 1, 1);
        inner.Controls.Add(credentials);

        inner.Controls.Add(new Label
        {
            Text = "Пароль передаётся только дочернему процессу через переменные окружения и не пишется в журнал. " +
                   "Без этих данных доступны только способы без учётных данных (LSA, Test-ComputerSecureChannel от текущей записи).",
            AutoSize = false,
            Width = 660,
            Height = 34,
            Font = Theme.FontSmall,
            ForeColor = Theme.TextMuted,
            Margin = new Padding(0, 0, 0, 10)
        });

        inner.Controls.Add(SectionTitle("Дополнительные действия"));

        var extras = new TableLayoutPanel
        {
            Width = 660,
            Height = 96,
            ColumnCount = 2,
            RowCount = 3,
            Margin = new Padding(0, 0, 0, 4)
        };
        extras.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        extras.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        for (int i = 0; i < 3; i++) extras.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));

        ConfigureCheck(_cbResetPassword, "Сбросить пароль компьютера", true, extras, 0, 0);
        ConfigureCheck(_cbPurgeKerberos, "Очистить кэш Kerberos", true, extras, 0, 1);
        ConfigureCheck(_cbFlushDns, "Сбросить кэш DNS", true, extras, 0, 2);
        ConfigureCheck(_cbRestartNetlogon, "Перезапустить Netlogon", true, extras, 1, 1);
        ConfigureCheck(_cbGpupdate, "Выполнить gpupdate /force", false, extras, 1, 2);
        ConfigureCheck(_cbVerify, "Проверить результат", true, extras, 1, 0);
        inner.Controls.Add(extras);

        var warning = new Label
        {
            Text = "Восстановление изменяет пароль учётной записи компьютера в Active Directory. " +
                   "Убедитесь, что компьютер — тот, который нужно восстановить, и что рядом нет " +
                   "пользователей с открытыми документами. При наличии резервной копии исходный " +
                   "секрет LSA сохраняется в папку ProgramData\\AdTrustRepair\\Backups.",
            AutoSize = false,
            Width = 660,
            Height = 66,
            BackColor = Theme.WarnBg,
            ForeColor = Theme.Warn,
            Font = Theme.FontSmall,
            Padding = new Padding(10, 8, 10, 8),
            Margin = new Padding(0, 8, 0, 0)
        };
        inner.Controls.Add(warning);

        _optionsPanel.Controls.Add(inner);
        return _optionsPanel;
    }

    private static void ConfigureCheck(CheckBox box, string text, bool value, TableLayoutPanel parent,
        int column, int row)
    {
        box.Text = text;
        box.Checked = value;
        box.AutoSize = true;
        box.Margin = new Padding(0, 2, 0, 0);
        parent.Controls.Add(box, column, row);
    }

    private static void AddOption(FlowLayoutPanel parent, RadioButton radio, string title, string description)
    {
        radio.Text = title;
        radio.AutoSize = true;
        radio.Checked = title.Contains("рекомендуется", StringComparison.Ordinal);
        radio.Margin = new Padding(0, 2, 0, 2);
        parent.Controls.Add(radio);

        parent.Controls.Add(new Label
        {
            Text = description,
            AutoSize = false,
            Width = 640,
            Height = 34,
            ForeColor = Theme.TextMuted,
            Font = Theme.FontSmall,
            Margin = new Padding(22, 0, 0, 8)
        });
    }

    private static Label SectionTitle(string text) => new()
    {
        Text = text,
        AutoSize = true,
        Font = Theme.FontBold,
        ForeColor = Theme.Text,
        Margin = new Padding(0, 2, 0, 6)
    };

    private Control BuildResults()
    {
        var host = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };
        host.Paint += (_, e) =>
        {
            var g = e.Graphics;
            var card = new Rectangle(0, 7, host.Width - 1, host.Height - 8);
            Theme.FillRounded(g, card, 12, Color.White);
            Theme.DrawRoundedBorder(g, card, 12, Theme.Border);
            TextRenderer.DrawText(g, "Ход выполнения", Theme.FontBold,
                new Rectangle(16, 14, host.Width - 32, 22), Theme.Text);
        };

        _resultBox.BorderStyle = BorderStyle.None;
        _resultBox.ReadOnly = true;
        _resultBox.BackColor = Color.FromArgb(249, 250, 252);
        _resultBox.Font = Theme.FontMono;
        _resultBox.DetectUrls = false;
        _resultBox.Location = new Point(14, 42);
        _resultBox.Size = new Size(host.Width - 28, host.Height - 58);
        _resultBox.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right | AnchorStyles.Bottom;
        host.Controls.Add(_resultBox);

        _statusLabel.AutoSize = false;
        _statusLabel.Location = new Point(14, 42);
        _statusLabel.Size = new Size(host.Width - 28, 22);
        _statusLabel.Anchor = AnchorStyles.Top | AnchorStyles.Left | AnchorStyles.Right;
        _statusLabel.Font = Theme.FontSmall;
        _statusLabel.ForeColor = Theme.TextMuted;
        _statusLabel.BackColor = Color.White;
        _statusLabel.Text = "Параметры можно изменить перед запуском.";
        host.Controls.Add(_statusLabel);
        _statusLabel.BringToFront();
        _resultBox.Location = new Point(14, 66);
        _resultBox.Size = new Size(host.Width - 28, host.Height - 82);

        return host;
    }

    private Control BuildFooter()
    {
        var panel = new Panel { Dock = DockStyle.Fill, BackColor = Theme.Bg };

        _passwordPanel.Size = new Size(380, 42);
        _passwordPanel.Location = new Point(0, 18);
        _passwordPanel.BackColor = Theme.Bg;
        _passwordPanel.Visible = false;
        var lbl = new Label
        {
            Text = "Новый пароль:",
            AutoSize = true,
            Location = new Point(0, 10),
            ForeColor = Theme.TextMuted,
            Font = Theme.FontSmall
        };
        _tbPassword.ReadOnly = true;
        _tbPassword.Location = new Point(84, 6);
        _tbPassword.Size = new Size(210, 26);
        _tbPassword.UseSystemPasswordChar = true;
        _tbPassword.Font = Theme.FontMono;
        _cbShowPassword.Text = "показать";
        _cbShowPassword.AutoSize = true;
        _cbShowPassword.Location = new Point(300, 9);
        _cbShowPassword.Font = Theme.FontSmall;
        _cbShowPassword.CheckedChanged += (_, _) => _tbPassword.UseSystemPasswordChar = !_cbShowPassword.Checked;
        _passwordPanel.Controls.Add(lbl);
        _passwordPanel.Controls.Add(_tbPassword);
        _passwordPanel.Controls.Add(_cbShowPassword);
        panel.Controls.Add(_passwordPanel);

        _btnPrimary.Width = 220;
        _btnPrimary.Height = 42;
        _btnPrimary.Location = new Point(panel.Width - 236, 14);
        _btnPrimary.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        _btnSecondary.Width = 130;
        _btnSecondary.Height = 42;
        _btnSecondary.Location = new Point(panel.Width - 376, 14);
        _btnSecondary.Anchor = AnchorStyles.Top | AnchorStyles.Right;
        panel.Controls.Add(_btnPrimary);
        panel.Controls.Add(_btnSecondary);
        return panel;
    }

    private void WireEvents()
    {
        _btnPrimary.Click += async (_, _) =>
        {
            if (_finished)
            {
                DialogResult = DialogResult.OK;
                Close();
                return;
            }

            await RunRepairAsync();
        };
        _btnSecondary.Click += (_, _) =>
        {
            if (_running)
            {
                _cts?.Cancel();
                return;
            }

            Close();
        };

        _repair.StepCompleted += step => SafeInvoke(() => AppendStep(step));
        _repair.ProgressChanged += text => SafeInvoke(() => _statusLabel.Text = text);

        foreach (var rb in new[] { _rbRcmp, _rbScp, _rbNetdom, _rbLsa, _rbKsetup })
            rb.CheckedChanged += (_, _) => UpdatePrimaryState();

        FormClosing += (_, e) =>
        {
            if (!_running) return;
            var answer = MessageBox.Show(this,
                "Восстановление ещё выполняется. Прервать и закрыть окно?",
                Text, MessageBoxButtons.YesNo, MessageBoxIcon.Warning);
            if (answer == DialogResult.Yes) _cts?.Cancel();
            else e.Cancel = true;
        };
    }

    private void UpdatePrimaryState()
    {
        _tbAdminUser.Enabled = true;
        _tbAdminPassword.Enabled = true;
    }

    private void CollectOptions()
    {
        var options = new RepairOptions
        {
            PreferredMethod = _rbScp.Checked ? ResetMethod.SecureChannelRepair
                : _rbNetdom.Checked ? ResetMethod.Netdom
                : _rbLsa.Checked ? ResetMethod.LsaNetUser
                : _rbKsetup.Checked ? ResetMethod.Ksetup
                : ResetMethod.ResetComputerMachinePassword,
            AllowFallbackMethods = _cbFallback.Checked,
            ResetMachinePassword = _cbResetPassword.Checked,
            PurgeKerberosTickets = _cbPurgeKerberos.Checked,
            FlushDns = _cbFlushDns.Checked,
            RestartNetlogon = _cbRestartNetlogon.Checked,
            ForceGroupPolicy = _cbGpupdate.Checked,
            VerifyAfterRepair = _cbVerify.Checked,
            DomainAdminUser = _tbAdminUser.Text.Trim(),
            DomainAdminPassword = _tbAdminPassword.Text,
            DsregLeaveBeforeKsetup = true
        };

        _currentOptions = options;
    }

    private RepairOptions? _currentOptions;

    private async Task RunRepairAsync()
    {
        if (_running || _finished) return;

        CollectOptions();
        var options = _currentOptions!;
        bool needsCredentials = options.PreferredMethod
            is ResetMethod.Netdom or ResetMethod.ResetComputerMachinePassword;
        if (needsCredentials &&
            (string.IsNullOrWhiteSpace(options.DomainAdminUser) ||
             string.IsNullOrWhiteSpace(options.DomainAdminPassword)))
        {
            MessageBox.Show(this,
                "Для выбранного способа укажите учётную запись и пароль администратора домена " +
                "или выберите «Экспертный: локальный сброс через LSA».",
                Text, MessageBoxButtons.OK, MessageBoxIcon.Warning);
            return;
        }

        string warning =
            "Будет выполнено восстановление доверия компьютера к домену " + _scan.DomainName + "." +
            Environment.NewLine + Environment.NewLine +
            "Способ: " + MethodName(options.PreferredMethod) + Environment.NewLine +
            (options.ResetMachinePassword
                ? "Пароль учётной записи компьютера будет изменён в Active Directory."
                : "Пароль компьютера меняться не будет (только восстановление канала).") +
            Environment.NewLine + Environment.NewLine +
            "Продолжить?";
        if (MessageBox.Show(this, warning, "Подтверждение восстановления",
                MessageBoxButtons.YesNo, MessageBoxIcon.Warning) != DialogResult.Yes)
            return;

        _running = true;
        _finished = false;
        _resultBox.Clear();
        _passwordPanel.Visible = false;
        Report = null;
        _btnPrimary.Enabled = false;
        _btnSecondary.Text = "Отмена";
        _btnSecondary.Enabled = true;
        _optionsPanel.Enabled = false;
        _statusLabel.Text = "Выполняется восстановление…";
        _cts = new CancellationTokenSource();

        try
        {
            var report = await _repair.RepairAsync(_scan, options, _cts.Token);
            Report = report;
            RenderResult(report);
        }
        catch (OperationCanceledException)
        {
            AppendLine("Восстановление отменено пользователем.", Theme.Warn);
            _statusLabel.Text = "Отменено.";
        }
        catch (Exception ex)
        {
            AppLog.Write("Ошибка восстановления: " + ex);
            AppendLine("Непредвиденная ошибка: " + ex.Message, Theme.Bad);
            _statusLabel.Text = "Завершено с ошибкой.";
        }
        finally
        {
            _running = false;
            _finished = true;
            _optionsPanel.Enabled = true;
            _btnPrimary.Enabled = true;
            _btnPrimary.Text = "Проверить компьютер снова";
            _btnSecondary.Text = "Закрыть";
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void RenderResult(RepairReport report)
    {
        if (report.NewPassword is { Length: > 0 })
        {
            _tbPassword.Text = report.NewPassword;
            _passwordPanel.Visible = true;
        }

        if (report.ErrorMessage is { Length: > 0 })
        {
            AppendLine("ОШИБКА: " + report.ErrorMessage, Theme.Bad);
            _statusLabel.Text = "Восстановление не выполнено.";
            return;
        }

        if (report.TrustRestored == true)
        {
            AppendLine("Готово: " + report.VerificationMessage, Theme.Good);
            _statusLabel.Text = "Доверие восстановлено успешно.";
            _statusLabel.ForeColor = Theme.Good;
        }
        else if (report.TrustRestored == false)
        {
            AppendLine("Доверие не подтверждено: " + report.VerificationMessage, Theme.Bad);
            _statusLabel.Text = "Доверие не восстановлено — смотрите подробности шагов.";
            _statusLabel.ForeColor = Theme.Bad;
        }
        else
        {
            AppendLine("Восстановление выполнено, но результат не проверялся.", Theme.Warn);
            _statusLabel.Text = "Проверка результата отключена.";
        }
    }

    private void AppendStep(RepairStepResult step)
    {
        Color color = step.Skipped ? Theme.TextMuted : step.Success ? Theme.Good : Theme.Bad;
        AppendLine((step.Skipped ? "• " : step.Success ? "✔ " : "✖ ") + step.Title, color);
        AppendLine("    " + step.Message, Theme.TextMuted);
    }

    private void AppendLine(string text, Color color)
    {
        _resultBox.SelectionStart = _resultBox.TextLength;
        _resultBox.SelectionLength = 0;
        _resultBox.SelectionColor = color;
        _resultBox.AppendText(text + Environment.NewLine);
        _resultBox.SelectionColor = _resultBox.ForeColor;
        _resultBox.ScrollToCaret();
    }

    private static string MethodName(ResetMethod method) => method switch
    {
        ResetMethod.ResetComputerMachinePassword => "Reset-ComputerMachinePassword",
        ResetMethod.LsaNetUser => "локальный (LSA + NetUserSetInfo)",
        ResetMethod.Netdom => "netdom resetpwd",
        ResetMethod.Ksetup => "ksetup /setcomputerpassword",
        ResetMethod.SecureChannelRepair => "Test-ComputerSecureChannel -Repair",
        _ => method.ToString()
    };

    private void SafeInvoke(Action action)
    {
        if (IsDisposed) return;
        if (InvokeRequired)
        {
            try
            {
                BeginInvoke(action);
            }
            catch (InvalidOperationException)
            {
                // окно закрыто
            }
        }
        else
        {
            action();
        }
    }
}
