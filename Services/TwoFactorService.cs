using OtpNet;
using QRCoder;

namespace SecureFileExchange2FA.Services;

public static class TwoFactorService
{
    public static string GenerateSecret()
    {
        var key = KeyGeneration.GenerateRandomKey(20);
        return Base32Encoding.ToString(key);
    }

    public static string GetQrCodeUri(string email, string secret)
    {
        return $"otpauth://totp/SecureFileExchange2FA:{email}?secret={secret}&issuer=SecureFileExchange2FA";
    }

    public static byte[] GenerateQrCodeImage(string uri)
    {
        using var qrGenerator = new QRCodeGenerator();
        using var qrCodeData = qrGenerator.CreateQrCode(uri, QRCodeGenerator.ECCLevel.Q);
        using var qrCode = new PngByteQRCode(qrCodeData);
        return qrCode.GetGraphic(20);
    }

    public static bool ValidateCode(string secret, string code)
    {
        var totp = new Totp(Base32Encoding.ToBytes(secret));
        return totp.VerifyTotp(code, out _, new VerificationWindow(2, 2));
    }
}
