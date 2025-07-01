using OtpNet;
using QRCoder;
using System;

namespace SecureFileExchange2FA
{
    public static class TwoFactorService
    {
        public static string GenerateSecret()
        {
            var bytes = KeyGeneration.GenerateRandomKey(20);
            return Base32Encoding.ToString(bytes);
        }

        public static string GetQrCodeUri(string email, string secret)
        {
            return $"otpauth://totp/SecureFileExchange2FA:{email}?secret={secret}&issuer=SecureFileExchange2FA";
        }

        public static byte[] GenerateQrCodeImage(string qrCodeUri)
        {
            using var qrGenerator = new QRCodeGenerator();
            using var qrCodeData = qrGenerator.CreateQrCode(qrCodeUri, QRCodeGenerator.ECCLevel.Q);
            using var qrCode = new PngByteQRCode(qrCodeData);
            return qrCode.GetGraphic(20);
        }

        public static bool ValidateCode(string secret, string code)
        {
            var bytes = Base32Encoding.ToBytes(secret);
            var totp = new Totp(bytes);
            return totp.VerifyTotp(code, out long _, new VerificationWindow(2, 2));
        }
    }
}
