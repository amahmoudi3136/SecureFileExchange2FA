using System.ComponentModel.DataAnnotations.Schema;

namespace SecureFileExchange2FA.Models
{
    [Table("Users")]
    public class User
    {
        public int Id { get; set; }
        public string Email { get; set; }
        public string PasswordHash { get; set; }
        public string TotpSecret { get; set; }
    }
}
