using Microsoft.EntityFrameworkCore;
using SecureFileExchange2FA.Models;

namespace SecureFileExchange2FA.Data
{
    public class ApplicationDbContext : DbContext
    {
        public ApplicationDbContext(DbContextOptions<ApplicationDbContext> options)
            : base(options)
        {
        }

        public DbSet<User> Users { get; set; }
    }
}
