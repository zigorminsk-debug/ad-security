using System.Security.Cryptography;
using System.Text;

namespace AdTrustRepair.Services;

/// <summary>Генерация нового пароля для учётной записи компьютера.</summary>
internal static class PasswordGenerator
{
    private const string Letters = "abcdefghijkmnopqrstuvwxyzABCDEFGHJKLMNPQRSTUVWXYZ";
    private const string Digits = "23456789";
    private const string Symbols = "!@#*-_=+?";

    public static string Generate(int length = 120)
    {
        if (length < 16) length = 16;
        const string all = Letters + Digits + Symbols;
        var chars = new char[length];
        // гарантируем все категории символов (требование сложности AD)
        chars[0] = Letters[RandomNumberGenerator.GetInt32(Letters.Length)];
        chars[1] = char.ToUpperInvariant(Letters[RandomNumberGenerator.GetInt32(Letters.Length)]);
        chars[2] = Digits[RandomNumberGenerator.GetInt32(Digits.Length)];
        chars[3] = Symbols[RandomNumberGenerator.GetInt32(Symbols.Length)];
        for (int i = 4; i < length; i++)
            chars[i] = all[RandomNumberGenerator.GetInt32(all.Length)];

        // перемешиваем (Фишер–Йетс)
        for (int i = length - 1; i > 0; i--)
        {
            int j = RandomNumberGenerator.GetInt32(i + 1);
            (chars[i], chars[j]) = (chars[j], chars[i]);
        }

        return new string(chars);
    }

    public static string Mask(string? secret)
    {
        if (string.IsNullOrEmpty(secret)) return "";
        return new string('•', Math.Min(secret.Length, 24));
    }

    public static string EncodeUtf8Base64(string text) => Convert.ToBase64String(Encoding.UTF8.GetBytes(text));
}
