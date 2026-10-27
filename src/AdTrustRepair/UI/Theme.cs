using System.Drawing.Drawing2D;

namespace AdTrustRepair.UI;

/// <summary>Цвета, шрифты и вспомогательные методы оформления.</summary>
internal static class Theme
{
    public static readonly Color Bg = Color.FromArgb(246, 247, 249);
    public static readonly Color Card = Color.White;
    public static readonly Color Border = Color.FromArgb(222, 226, 232);
    public static readonly Color Text = Color.FromArgb(30, 34, 42);
    public static readonly Color TextMuted = Color.FromArgb(100, 108, 120);
    public static readonly Color Accent = Color.FromArgb(21, 101, 192);
    public static readonly Color AccentDark = Color.FromArgb(15, 76, 145);
    public static readonly Color Good = Color.FromArgb(27, 128, 62);
    public static readonly Color GoodBg = Color.FromArgb(231, 246, 236);
    public static readonly Color Warn = Color.FromArgb(154, 101, 0);
    public static readonly Color WarnBg = Color.FromArgb(255, 246, 224);
    public static readonly Color Bad = Color.FromArgb(178, 34, 34);
    public static readonly Color BadBg = Color.FromArgb(253, 234, 234);
    public static readonly Color Idle = Color.FromArgb(110, 118, 130);
    public static readonly Color IdleBg = Color.FromArgb(238, 240, 243);

    public static readonly Font FontBase = new("Segoe UI", 9.75f);
    public static readonly Font FontSmall = new("Segoe UI", 8.75f);
    public static readonly Font FontBold = new("Segoe UI", 9.75f, FontStyle.Bold);
    public static readonly Font FontH1 = new("Segoe UI Semibold", 16f);
    public static readonly Font FontH2 = new("Segoe UI Semibold", 12.5f);
    public static readonly Font FontMono = new("Consolas", 9.25f);
    public static readonly Font FontLogo = new("Segoe UI Semibold", 15f);
    public static readonly Font FontGlyphLarge = new("Segoe UI Semibold", 17f, FontStyle.Bold);
    public static readonly Font FontGlyphMedium = new("Segoe UI Semibold", 10.5f, FontStyle.Bold);
    public static readonly Font FontGlyphWarning = new("Segoe UI Semibold", 16f, FontStyle.Bold);

    /// <summary>Скруглённый прямоугольник (для карточек и «пилюль»).</summary>
    public static GraphicsPath RoundedRect(Rectangle r, int radius)
    {
        int d = Math.Max(2, radius * 2);
        var path = new GraphicsPath();
        if (r.Width <= d || r.Height <= d)
        {
            path.AddRectangle(r);
            return path;
        }

        path.AddArc(r.X, r.Y, d, d, 180, 90);
        path.AddArc(r.Right - d, r.Y, d, d, 270, 90);
        path.AddArc(r.Right - d, r.Bottom - d, d, d, 0, 90);
        path.AddArc(r.X, r.Bottom - d, d, d, 90, 90);
        path.CloseFigure();
        return path;
    }

    public static void FillRounded(Graphics g, Rectangle rect, int radius, Color color)
    {
        using var path = RoundedRect(rect, radius);
        using var brush = new SolidBrush(color);
        g.FillPath(brush, path);
    }

    public static void DrawRoundedBorder(Graphics g, Rectangle rect, int radius, Color color, float width = 1f)
    {
        using var path = RoundedRect(rect, radius);
        using var pen = new Pen(color, width);
        g.DrawPath(pen, path);
    }

    /// <summary>Цвета и значок для статуса проверки.</summary>
    public static (Color Fg, Color Bg, string Glyph) StatusVisual(Models.CheckStatus status) => status switch
    {
        Models.CheckStatus.Ok => (Good, GoodBg, "\u2713"),
        Models.CheckStatus.Warning => (Warn, WarnBg, "!"),
        Models.CheckStatus.Error => (Bad, BadBg, "\u2715"),
        Models.CheckStatus.NotApplicable => (Idle, IdleBg, "\u2013"),
        _ => (Idle, IdleBg, "i")
    };

    public static void EnableDoubleBuffering(Control c)
    {
        typeof(Control).GetProperty("DoubleBuffered",
            System.Reflection.BindingFlags.Instance | System.Reflection.BindingFlags.NonPublic)
            ?.SetValue(c, true);
    }

    public static Button MakePrimaryButton(string text)
    {
        var b = new Button
        {
            Text = text,
            AutoSize = false,
            Height = 40,
            Width = 210,
            FlatStyle = FlatStyle.Flat,
            BackColor = Accent,
            ForeColor = Color.White,
            Font = FontBold,
            Cursor = Cursors.Hand,
            UseVisualStyleBackColor = false
        };
        b.FlatAppearance.BorderSize = 0;
        b.FlatAppearance.MouseOverBackColor = AccentDark;
        b.FlatAppearance.MouseDownBackColor = AccentDark;
        return b;
    }

    public static Button MakeSecondaryButton(string text, int width = 150)
    {
        var b = new Button
        {
            Text = text,
            FlatStyle = FlatStyle.Flat,
            BackColor = Color.White,
            ForeColor = Text,
            Font = FontBase,
            Height = 36,
            Width = width,
            Cursor = Cursors.Hand,
            UseVisualStyleBackColor = false
        };
        b.FlatAppearance.BorderColor = Border;
        b.FlatAppearance.MouseOverBackColor = Color.FromArgb(242, 244, 247);
        return b;
    }

    public static Label MakeLabel(string text, Font? font = null, Color? color = null)
        => new()
        {
            Text = text,
            AutoSize = true,
            Font = font ?? FontBase,
            ForeColor = color ?? Text,
            BackColor = Color.Transparent
        };
}
