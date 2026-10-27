using System.Diagnostics;
using AdTrustRepair.Models;
using AdTrustRepair.Services;

namespace AdTrustRepair.UI;

public sealed class MainForm : Form
{
    private readonly DiagnosticsService _diagnostics = new();

    private readonly HeaderPanel _header = new();
    private readonly StatusCard _statusCard = new();
    private readonly Button _btnScan = Theme.MakeSecondaryButton("Проверить компьютер", 344);
    private readonly Button _btnRepair = Theme.MakePrimaryButton("Восстановить доверие");
    private readonly Button _btnSave = Theme.MakeSecondaryButton("Сохранить отчёт", 166);
    private readonly Button _btnCopy = Theme.MakeSecondaryButton("Копировать отчёт", 166);
    private readonly LinkLabel _lnkLog = new();
    private readonly Label _lblProgress = new();
    private readonly ProgressBar _progress = new();
    private readonly FlowLayoutPanel _checkList = new();
    private readonly Label _checksCaption = new();
    private readonly Label _detailTitle = new();
    private readonly Label _detailSummary = new();
    private readonly TextBox _detailDetails = new();
    private readonly TextBox _recommendations = new();
    private readonly TextBox _log = new();
    private readonly SegmentButton _segChecks = new("Проверки");
    private readonly SegmentButton _segRecs = new("Рекомендации");
    private readonly SegmentButton _segLog = new("Журнал");
    private readonly Panel _pageChecks = new();
    private readonly Panel _pageRecs = new();
    private readonly Panel _pageLog = new();
    private readonly Panel _contentHost = new();

    private ScanReport? _report;
    private CancellationTokenSource? _cts;
    private RepairReport? _lastRepair;
    private CheckRow? _selectedRow;
    private bool _busy;
    private int _checksAdded;

    public MainForm()
    {
        Text = Program.AppTitle;
        BackColor = Theme.Bg;
        Font = Theme.FontBase;
        StartPosition = FormStartPosition.CenterScreen;
        ClientSize = new Size(1220, 830);
        MinimumSize = new Size(1060, 720);
        KeyPreview = true;

        try
        {
            Icon = Icon.ExtractAssociatedIcon(Application.ExecutablePath);
        }
        catch
        {
            // иконка не критична
        }

        BuildLayout();
        WireEvents();
        _btnSave.Enabled = false;
        _btnCopy.Enabled = false;

        Shown += async (_, _) => await RunScanAsync();
        KeyDown += (_, e) =>
        {
            if (e.KeyCode == Keys.F5) _ = RunScanAsync();
            if (e.KeyCode == Keys.Escape && _busy) _cts?.Cancel();
        };
    }

    // ------------------------------------------------------------------
    // Построение интерфейса
    // ------------------------------------------------------------------

    private void BuildLayout()
    {
        _header.Title = "AD Trust Repair";
        _header.Subtitle = "Диагностика и восстановление доверительных отношений компьютера с доменом Active Directory";

        var root = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            Padding = new Padding(18, 16, 18, 18),
            ColumnCount = 2,
            RowCount = 1,
            BackColor = Theme.Bg
        };
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Absolute, 376));
        root.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 100));
        root.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        root.Controls.Add(BuildLeftColumn(), 0, 0);
        root.Controls.Add(BuildRightColumn(), 1, 0);

        // порядок добавления важен: сначала заполняющая область, затем док-панель сверху
        Controls.Add(root);
        Controls.Add(_header);
    }

    private Control BuildLeftColumn()
    {
        var flow = new FlowLayoutPanel
        {
            Dock = DockStyle.Fill,
            FlowDirection = FlowDirection.TopDown,
            WrapContents = false,
            AutoScroll = false,
            BackColor = Theme.Bg,
            Padding = new Padding(0, 0, 12, 0)
        };

        _statusCard.Width = 344;
        _statusCard.Margin = new Padding(0, 0, 0, 14);
        flow.Controls.Add(_statusCard);

        _btnRepair.Width = 344;
        _btnRepair.Height = 46;
        _btnRepair.Margin = new Padding(0, 0, 0, 10);
        _btnRepair.Enabled = false;
        flow.Controls.Add(_btnRepair);

        _btnScan.Width = 344;
        _btnScan.Height = 42;
        _btnScan.Margin = new Padding(0, 0, 0, 6);
        flow.Controls.Add(_btnScan);

        var row = new TableLayoutPanel
        {
            Width = 344,
            Height = 40,
            ColumnCount = 2,
            RowCount = 1,
            Margin = new Padding(0, 0, 0, 8)
        };
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        row.ColumnStyles.Add(new ColumnStyle(SizeType.Percent, 50));
        _btnSave.Width = 166;
        _btnCopy.Width = 166;
        _btnSave.Margin = new Padding(0, 0, 4, 0);
        _btnCopy.Margin = new Padding(4, 0, 0, 0);
        row.Controls.Add(_btnSave, 0, 0);
        row.Controls.Add(_btnCopy, 1, 0);
        flow.Controls.Add(row);

        _lnkLog.Text = "Открыть файл журнала";
        _lnkLog.AutoSize = true;
        _lnkLog.Font = Theme.FontSmall;
        _lnkLog.LinkColor = Theme.Accent;
        _lnkLog.Margin = new Padding(2, 0, 0, 10);
        flow.Controls.Add(_lnkLog);

        _lblProgress.AutoSize = false;
        _lblProgress.Width = 344;
        _lblProgress.Height = 22;
        _lblProgress.Font = Theme.FontSmall;
        _lblProgress.ForeColor = Theme.TextMuted;
        _lblProgress.Text = "";
        _lblProgress.Margin = new Padding(0, 0, 0, 2);
        flow.Controls.Add(_lblProgress);

        _progress.Width = 344;
        _progress.Height = 8;
        _progress.Style = ProgressBarStyle.Marquee;
        _progress.MarqueeAnimationSpeed = 0;
        _progress.Margin = new Padding(0, 0, 0, 14);
        flow.Controls.Add(_progress);

        var hint = new Label
        {
            Width = 344,
            Height = 150,
            AutoSize = false,
            Font = Theme.FontSmall,
            ForeColor = Theme.TextMuted,
            Margin = new Padding(0, 6, 0, 0),
            Text = "Программа работает локально и не отправляет данные.\n\n" +
                   "Что проверяется: членство в домене, DNS и доступность контроллера, " +
                   "защищённый канал, Kerberos, время, службы, политики и журналы NETLOGON.\n\n" +
                   "Восстановление меняет пароль учётной записи компьютера в AD — выполняйте его " +
                   "только при подтверждённой потере доверия."
        };
        flow.Controls.Add(hint);

        return flow;
    }

    private Control BuildRightColumn()
    {
        var card = new Panel { Dock = DockStyle.Fill, BackColor = Color.White, Padding = new Padding(1) };
        card.Paint += (_, e) =>
        {
            using var pen = new Pen(Theme.Border);
            e.Graphics.DrawRectangle(pen, 0, 0, card.Width - 1, card.Height - 1);
        };

        var toolbar = new Panel { Dock = DockStyle.Top, Height = 58, BackColor = Color.White };
        toolbar.Paint += (_, e) =>
        {
            using var pen = new Pen(Theme.Border);
            e.Graphics.DrawLine(pen, 12, toolbar.Height - 1, toolbar.Width - 12, toolbar.Height - 1);
        };
        _segChecks.Location = new Point(8, 12);
        _segRecs.Location = new Point(148, 12);
        _segLog.Location = new Point(288, 12);
        toolbar.Controls.Add(_segChecks);
        toolbar.Controls.Add(_segRecs);
        toolbar.Controls.Add(_segLog);

        _contentHost.Dock = DockStyle.Fill;
        _contentHost.BackColor = Color.White;
        card.Controls.Add(_contentHost);
        card.Controls.Add(toolbar);

        BuildChecksPage();
        BuildTextPage(_pageRecs, _recommendations);
        BuildTextPage(_pageLog, _log);
        _log.Font = Theme.FontMono;

        foreach (var page in new[] { _pageChecks, _pageRecs, _pageLog })
        {
            page.Dock = DockStyle.Fill;
            page.Visible = false;
            page.BackColor = Color.White;
            _contentHost.Controls.Add(page);
        }

        return card;
    }

    private void BuildChecksPage()
    {
        var split = new SplitContainer
        {
            Dock = DockStyle.Fill,
            Orientation = Orientation.Horizontal,
            SplitterWidth = 8,
            BackColor = Color.White,
            Panel1MinSize = 160,
            Panel2MinSize = 140
        };
        split.Panel1.BackColor = Color.White;
        split.Panel2.BackColor = Color.White;

        _checksCaption.Dock = DockStyle.Top;
        _checksCaption.Height = 34;
        _checksCaption.Font = Theme.FontBold;
        _checksCaption.ForeColor = Theme.Text;
        _checksCaption.TextAlign = ContentAlignment.MiddleLeft;
        _checksCaption.Padding = new Padding(4, 0, 0, 0);
        _checksCaption.Text = "Проверки";

        _checkList.Dock = DockStyle.Fill;
        _checkList.FlowDirection = FlowDirection.TopDown;
        _checkList.WrapContents = false;
        _checkList.AutoScroll = true;
        _checkList.BackColor = Color.White;
        _checkList.Padding = new Padding(2, 2, 2, 8);
        _checkList.SizeChanged += (_, _) => ResizeRows();
        split.Panel1.Controls.Add(_checkList);
        split.Panel1.Controls.Add(_checksCaption);

        var details = new TableLayoutPanel
        {
            Dock = DockStyle.Fill,
            ColumnCount = 1,
            RowCount = 3,
            BackColor = Color.White,
            Padding = new Padding(4, 4, 4, 4)
        };
        details.RowStyles.Add(new RowStyle(SizeType.Absolute, 30));
        details.RowStyles.Add(new RowStyle(SizeType.Absolute, 42));
        details.RowStyles.Add(new RowStyle(SizeType.Percent, 100));

        _detailTitle.Dock = DockStyle.Fill;
        _detailTitle.Font = Theme.FontH2;
        _detailTitle.TextAlign = ContentAlignment.MiddleLeft;
        _detailTitle.Text = "Подробности проверки";
        details.Controls.Add(_detailTitle, 0, 0);

        _detailSummary.Dock = DockStyle.Fill;
        _detailSummary.Font = Theme.FontBase;
        _detailSummary.ForeColor = Theme.TextMuted;
        _detailSummary.TextAlign = ContentAlignment.TopLeft;
        details.Controls.Add(_detailSummary, 0, 1);

        _detailDetails.Dock = DockStyle.Fill;
        _detailDetails.Multiline = true;
        _detailDetails.ReadOnly = true;
        _detailDetails.ScrollBars = ScrollBars.Both;
        _detailDetails.WordWrap = false;
        _detailDetails.BorderStyle = BorderStyle.None;
        _detailDetails.Font = Theme.FontMono;
        _detailDetails.BackColor = Color.FromArgb(249, 250, 252);
        _detailDetails.ForeColor = Theme.Text;
        details.Controls.Add(_detailDetails, 0, 2);

        split.Panel2.Controls.Add(details);
        _pageChecks.Controls.Add(split);

        Shown += (_, _) =>
        {
            try
            {
                split.SplitterDistance = Math.Max(220, split.Height * 55 / 100);
            }
            catch
            {
                // SplitterDistance может не примениться до первой отрисовки
            }
        };
    }

    private static void BuildTextPage(Panel page, TextBox box)
    {
        box.Dock = DockStyle.Fill;
        box.Multiline = true;
        box.ReadOnly = true;
        box.ScrollBars = ScrollBars.Both;
        box.WordWrap = false;
        box.BorderStyle = BorderStyle.None;
        box.BackColor = Color.White;
        box.Font = Theme.FontBase;
        box.Padding = new Padding(8);
        page.Controls.Add(box);
    }

    private void ShowPage(int index)
    {
        _pageChecks.Visible = index == 0;
        _pageRecs.Visible = index == 1;
        _pageLog.Visible = index == 2;
        _pageChecks.BringToFront();
        _pageRecs.BringToFront();
        _pageLog.BringToFront();

        _segChecks.Active = index == 0;
        _segRecs.Active = index == 1;
        _segLog.Active = index == 2;
    }

    private void WireEvents()
    {
        _btnScan.Click += async (_, _) => await RunScanAsync();
        _btnRepair.Click += async (_, _) => await StartRepairAsync();
        _btnSave.Click += (_, _) => SaveReport();
        _btnCopy.Click += (_, _) => CopyReport();
        _lnkLog.LinkClicked += (_, _) => OpenLogFile();

        _segChecks.Click += (_, _) => ShowPage(0);
        _segRecs.Click += (_, _) => ShowPage(1);
        _segLog.Click += (_, _) => ShowPage(2);

        _diagnostics.ProgressChanged += text => SafeInvoke(() => _lblProgress.Text = text);
        _diagnostics.CheckCompleted += check => SafeInvoke(() => AddCheckRow(check));

        AppLog.LineAdded += line => SafeInvoke(() =>
        {
            if (!_log.IsDisposed) _log.AppendText(line + Environment.NewLine);
        });

        ShowPage(0);
    }

    // ------------------------------------------------------------------
    // Сканирование
    // ------------------------------------------------------------------

    private async Task RunScanAsync()
    {
        if (_busy) return;
        _busy = true;
        SetBusy(true);

        _checkList.SuspendLayout();
        _checkList.Controls.Clear();
        _checkList.ResumeLayout();
        _selectedRow = null;
        _checksAdded = 0;
        _checksCaption.Text = "Проверки";
        _detailTitle.Text = "Подробности проверки";
        _detailSummary.Text = "";
        _detailDetails.Text = "";
        _recommendations.Text = "";
        _statusCard.Status = CheckStatus.Info;
        _statusCard.Title = "Идёт проверка…";
        _statusCard.Subtitle = "Выполняется диагностика компьютера и домена.";
        _statusCard.Line1 = "";
        _statusCard.Line2 = "";
        _statusCard.Stats = "";
        _statusCard.Busy = true;
        _statusCard.Invalidate();
        ShowPage(0);

        _cts = new CancellationTokenSource();
        try
        {
            var report = await _diagnostics.ScanAsync(_cts.Token);
            _report = report;
            RenderReport(report);
        }
        catch (OperationCanceledException)
        {
            _lblProgress.Text = "Проверка отменена.";
            _statusCard.Busy = false;
            _statusCard.Status = CheckStatus.NotApplicable;
            _statusCard.Title = "Проверка отменена";
            _statusCard.Subtitle = "Нажмите «Проверить компьютер», чтобы запустить снова.";
            _statusCard.Invalidate();
        }
        catch (Exception ex)
        {
            AppLog.Write("Ошибка диагностики: " + ex);
            MessageBox.Show(this, "Не удалось выполнить проверку:\n\n" + ex.Message, Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
        finally
        {
            _busy = false;
            SetBusy(false);
            _cts?.Dispose();
            _cts = null;
        }
    }

    private void RenderReport(ScanReport report)
    {
        _report = report;
        _statusCard.Busy = false;
        _statusCard.Status = report.OverallStatus;
        _statusCard.Title = report.OverallTitle;
        _statusCard.Subtitle = report.IsDomainJoined
            ? $"Домен: {report.DomainName}"
            : "Компьютер не входит в домен — доверие не проверялось.";
        _statusCard.Line1 = $"Компьютер: {report.ComputerName} ({report.Fqdn})";
        _statusCard.Line2 = report.DomainController is { Length: > 0 }
            ? $"Контроллер домена: {report.DomainController}"
            : "Контроллер домена не определён";
        _statusCard.Stats = $"Проверок: {report.Checks.Count}   •   " +
                            $"ошибок: {report.Count(CheckStatus.Error)}   •   " +
                            $"предупреждений: {report.Count(CheckStatus.Warning)}";
        _statusCard.Invalidate();

        _header.MachineText = report.IsDomainJoined
            ? $"{report.ComputerName}  •  {report.DomainName}"
            : report.ComputerName;
        _header.Invalidate();

        _checksCaption.Text = $"Проверки ({report.Checks.Count})";
        _recommendations.Text = report.Recommendations.Count == 0
            ? "Рекомендаций нет."
            : string.Join(Environment.NewLine + Environment.NewLine,
                report.Recommendations.Select((r, i) => $"{i + 1}. {r}"));

        if (report.Recommendations.Count > 0 && report.OverallStatus == CheckStatus.Error)
            ShowPage(1);

        var toSelect = report.Checks.FirstOrDefault(c => c.Status == CheckStatus.Error)
                       ?? report.Checks.FirstOrDefault(c => c.Status == CheckStatus.Warning)
                       ?? report.Checks.FirstOrDefault();
        if (toSelect != null) SelectCheck(toSelect);

        _lblProgress.Text = $"Проверка завершена: {report.FinishedLocal:HH:mm:ss}";
        _btnRepair.Enabled = report.IsDomainJoined;
        _btnSave.Enabled = true;
        _btnCopy.Enabled = true;
    }

    private void AddCheckRow(CheckResult check)
    {
        var row = new CheckRow();
        row.Bind(check);
        row.Width = Math.Max(200, _checkList.ClientSize.Width - 26);
        row.Click += (_, _) => SelectCheck(check);
        _checkList.Controls.Add(row);
        _checksAdded++;
        _checksCaption.Text = $"Проверки ({_checksAdded})";
        if (check.Status == CheckStatus.Error && _selectedRow == null) SelectCheck(check);
    }

    private void SelectCheck(CheckResult check)
    {
        CheckRow? target = null;
        foreach (Control control in _checkList.Controls)
        {
            if (control is not CheckRow row) continue;
            bool isTarget = ReferenceEquals(row.Result, check);
            row.Selected = isTarget;
            row.Invalidate();
            if (isTarget) target = row;
        }

        _selectedRow = target;
        _detailTitle.Text = check.Title;
        _detailSummary.Text = check.Summary;
        var (_, _, glyph) = Theme.StatusVisual(check.Status);
        _detailDetails.Text = $"Статус: {check.StatusText} {glyph}    Длительность: {check.Duration.TotalSeconds:0.0} с" +
                              Environment.NewLine +
                              new string('-', 60) + Environment.NewLine +
                              check.Details;
        _detailDetails.SelectionLength = 0;
        _detailDetails.SelectionStart = 0;
        if (target != null) _checkList.ScrollControlIntoView(target);
    }

    private void ResizeRows()
    {
        int width = Math.Max(200, _checkList.ClientSize.Width - 26);
        foreach (Control control in _checkList.Controls)
            if (control is CheckRow row) row.Width = width;
    }

    private void SetBusy(bool busy)
    {
        _btnScan.Enabled = !busy;
        _btnRepair.Enabled = !busy && _report?.IsDomainJoined == true;
        _progress.MarqueeAnimationSpeed = busy ? 30 : 0;
        _lblProgress.Text = busy ? "Проверка выполняется…" : _lblProgress.Text;
        Cursor = busy ? Cursors.AppStarting : Cursors.Default;
        if (!busy) _statusCard.Busy = false;
    }

    // ------------------------------------------------------------------
    // Восстановление
    // ------------------------------------------------------------------

    private async Task StartRepairAsync()
    {
        if (_busy || _report == null) return;
        if (!_report.IsDomainJoined)
        {
            MessageBox.Show(this, "Компьютер не входит в домен — восстанавливать доверие не требуется.",
                Program.AppTitle, MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var form = new RepairForm(_report);
        var result = form.ShowDialog(this);
        if (form.Report != null)
        {
            _lastRepair = form.Report;
            _log.AppendText(Environment.NewLine + ReportWriter.ToText(form.Report) + Environment.NewLine);
        }

        if (result == DialogResult.OK)
            await RunScanAsync();
    }

    private void SaveReport()
    {
        if (_report == null)
        {
            MessageBox.Show(this, "Сначала выполните проверку.", Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
            return;
        }

        using var dialog = new SaveFileDialog
        {
            Filter = "Текстовый отчёт (*.txt)|*.txt|Все файлы (*.*)|*.*",
            FileName = $"AdTrustRepair-{_report.ComputerName}-{DateTime.Now:yyyyMMdd-HHmm}.txt"
        };
        if (dialog.ShowDialog(this) != DialogResult.OK) return;

        try
        {
            string text = ReportWriter.ToText(_report);
            if (_lastRepair != null)
                text += Environment.NewLine + Environment.NewLine + ReportWriter.ToText(_lastRepair);
            File.WriteAllText(dialog.FileName, text);
            MessageBox.Show(this, "Отчёт сохранён:\n" + dialog.FileName, Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Information);
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Не удалось сохранить отчёт: " + ex.Message, Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void CopyReport()
    {
        if (_report == null) return;
        try
        {
            Clipboard.SetText(ReportWriter.ToText(_report));
            _lblProgress.Text = "Отчёт скопирован в буфер обмена.";
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Не удалось скопировать отчёт: " + ex.Message, Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

    private void OpenLogFile()
    {
        try
        {
            Process.Start(new ProcessStartInfo("explorer.exe", "/select,\"" + AppLog.FilePath + "\"")
            {
                UseShellExecute = true
            });
        }
        catch (Exception ex)
        {
            MessageBox.Show(this, "Не удалось открыть журнал: " + ex.Message, Program.AppTitle,
                MessageBoxButtons.OK, MessageBoxIcon.Error);
        }
    }

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
                // окно закрывается
            }
        }
        else
        {
            action();
        }
    }
}
