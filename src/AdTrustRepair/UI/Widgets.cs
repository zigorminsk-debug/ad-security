using AdTrustRepair.Models;

namespace AdTrustRepair.UI;

/// <summary>Шапка окна.</summary>
internal sealed class HeaderPanel : Control
{
    public string Title { get; set; } = "AD Trust Repair";
    public string Subtitle { get; set; } = "";
    public string MachineText { get; set; } = "";

    public HeaderPanel()
    {
        Theme.EnableDoubleBuffering(this);
        Height = 92;
        Dock = DockStyle.Top;
        BackColor = Theme.Bg;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.Clear(Theme.Bg);
        using (var white = new SolidBrush(Color.White)) g.FillRectangle(white, new Rectangle(0, 0, Width, Height - 1));
        using (var line = new Pen(Theme.Border)) g.DrawLine(line, 0, Height - 1, Width, Height - 1);

        var logo = new Rectangle(24, 22, 46, 46);
        Theme.FillRounded(g, logo, 12, Theme.Accent);
        TextRenderer.DrawText(g, "AD", Theme.FontLogo, logo, Color.White,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        TextRenderer.DrawText(g, Title, Theme.FontH1,
            new Rectangle(84, 18, Width - 400, 30), Theme.Text,
            TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g, Subtitle, Theme.FontSmall,
            new Rectangle(85, 48, Math.Max(120, Width - 420), 22), Theme.TextMuted,
            TextFormatFlags.Left | TextFormatFlags.EndEllipsis);

        if (!string.IsNullOrEmpty(MachineText))
        {
            var font = Theme.FontSmall;
            var size = TextRenderer.MeasureText(g, MachineText, font);
            var pill = new Rectangle(Width - size.Width - 48, 32, size.Width + 24, 26);
            Theme.FillRounded(g, pill, 13, Color.FromArgb(240, 244, 250));
            TextRenderer.DrawText(g, MachineText, font, pill, Theme.AccentDark,
                TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
        }
    }
}

/// <summary>Карточка с итогом проверки.</summary>
internal sealed class StatusCard : Control
{
    public CheckStatus Status { get; set; } = CheckStatus.NotApplicable;
    public string Title { get; set; } = "Проверка не запускалась";
    public string Subtitle { get; set; } = "Нажмите «Проверить компьютер».";
    public string Line1 { get; set; } = "";
    public string Line2 { get; set; } = "";
    public string Stats { get; set; } = "";
    public bool Busy { get; set; }

    public StatusCard()
    {
        Theme.EnableDoubleBuffering(this);
        Height = 214;
        Dock = DockStyle.Top;
        BackColor = Theme.Bg;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.Clear(Theme.Bg);

        var card = new Rectangle(0, 0, Width - 1, Height - 1);
        Theme.FillRounded(g, card, 12, Theme.Card);
        Theme.DrawRoundedBorder(g, card, 12, Theme.Border);

        var (fg, bg, glyph) = Theme.StatusVisual(Status);
        if (Busy) (fg, bg, glyph) = (Theme.Accent, Color.FromArgb(232, 240, 252), "…");

        var icon = new Rectangle(18, 18, 46, 46);
        Theme.FillRounded(g, icon, 23, bg);
        TextRenderer.DrawText(g, glyph, Theme.FontGlyphLarge, icon, fg,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        TextRenderer.DrawText(g, Title, Theme.FontH2,
            new Rectangle(78, 20, Width - 96, 28), fg,
            TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g, Subtitle, Theme.FontSmall,
            new Rectangle(79, 48, Width - 100, 40), Theme.TextMuted,
            TextFormatFlags.Left | TextFormatFlags.WordBreak);

        int y = 104;
        using (var line = new Pen(Theme.Border)) g.DrawLine(line, 18, y, Width - 20, y);
        y += 12;

        if (!string.IsNullOrEmpty(Line1))
        {
            TextRenderer.DrawText(g, Line1, Theme.FontSmall, new Rectangle(18, y, Width - 36, 20), Theme.TextMuted,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
            y += 22;
        }

        if (!string.IsNullOrEmpty(Line2))
        {
            TextRenderer.DrawText(g, Line2, Theme.FontSmall, new Rectangle(18, y, Width - 36, 20), Theme.TextMuted,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
            y += 22;
        }

        if (!string.IsNullOrEmpty(Stats))
        {
            y = Math.Min(y + 4, Height - 34);
            TextRenderer.DrawText(g, Stats, Theme.FontBold, new Rectangle(18, y, Width - 36, 24), Theme.Text,
                TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        }
    }
}

/// <summary>Строка списка проверок.</summary>
internal sealed class CheckRow : Control
{
    private bool _hover;

    public CheckResult? Result { get; private set; }
    public bool Selected { get; set; }

    public CheckRow()
    {
        Theme.EnableDoubleBuffering(this);
        Height = 68;
        Margin = new Padding(0, 0, 0, 8);
        Cursor = Cursors.Hand;
        BackColor = Color.White;
    }

    public void Bind(CheckResult result)
    {
        Result = result;
        AccessibleName = result.Title;
        Invalidate();
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        if (Result == null) return;
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.Clear(Color.White);

        var (fg, bg, glyph) = Theme.StatusVisual(Result.Status);
        var rect = new Rectangle(0, 0, Width - 1, Height - 1);
        Color fill = Selected ? Color.FromArgb(240, 246, 255) : _hover ? Color.FromArgb(248, 249, 251) : Color.White;
        Theme.FillRounded(g, rect, 10, fill);
        Theme.DrawRoundedBorder(g, rect, 10, Selected ? Theme.Accent : Theme.Border, Selected ? 1.6f : 1f);

        var icon = new Rectangle(12, (Height - 30) / 2, 30, 30);
        Theme.FillRounded(g, icon, 15, bg);
        TextRenderer.DrawText(g, glyph, Theme.FontGlyphMedium, icon, fg,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);

        int textWidth = Math.Max(40, Width - 82 - 82);
        TextRenderer.DrawText(g, Result.Title, Theme.FontBold,
            new Rectangle(52, 12, textWidth, 22), Theme.Text,
            TextFormatFlags.Left | TextFormatFlags.EndEllipsis);
        TextRenderer.DrawText(g, Result.Summary, Theme.FontSmall,
            new Rectangle(53, 34, textWidth, 24), Theme.TextMuted,
            TextFormatFlags.Left | TextFormatFlags.EndEllipsis);

        var pill = new Rectangle(Width - 82, (Height - 24) / 2, 68, 24);
        Theme.FillRounded(g, pill, 12, bg);
        TextRenderer.DrawText(g, Result.StatusText, Theme.FontSmall, pill, fg,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter | TextFormatFlags.EndEllipsis);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hover = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hover = false;
        Invalidate();
        base.OnMouseLeave(e);
    }
}

/// <summary>Плоская кнопка-раздел (сегментированный переключатель).</summary>
internal sealed class SegmentButton : Control
{
    private bool _active;
    private bool _hover;

    public bool Active
    {
        get => _active;
        set
        {
            _active = value;
            Invalidate();
        }
    }

    public SegmentButton(string text)
    {
        Text = text;
        Theme.EnableDoubleBuffering(this);
        Height = 36;
        Width = 136;
        Font = Theme.FontBold;
        Cursor = Cursors.Hand;
    }

    protected override void OnPaint(PaintEventArgs e)
    {
        var g = e.Graphics;
        g.SmoothingMode = System.Drawing.Drawing2D.SmoothingMode.AntiAlias;
        g.Clear(Parent?.BackColor ?? Color.White);

        if (_active || _hover)
        {
            var pill = new Rectangle(0, (Height - 30) / 2, Width - 1, 30);
            Theme.FillRounded(g, pill, 8, _active ? Color.FromArgb(230, 239, 252) : Color.FromArgb(244, 246, 249));
        }

        TextRenderer.DrawText(g, Text, Theme.FontBold, ClientRectangle,
            _active ? Theme.AccentDark : Theme.TextMuted,
            TextFormatFlags.HorizontalCenter | TextFormatFlags.VerticalCenter);
    }

    protected override void OnMouseEnter(EventArgs e)
    {
        _hover = true;
        Invalidate();
        base.OnMouseEnter(e);
    }

    protected override void OnMouseLeave(EventArgs e)
    {
        _hover = false;
        Invalidate();
        base.OnMouseLeave(e);
    }
}
