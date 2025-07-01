using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using SecureFileExchange2FA.Data;
using SecureFileExchange2FA.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;
using System.Threading.Tasks;
using Microsoft.EntityFrameworkCore; 

namespace SecureFileExchange2FA.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly ApplicationDbContext _context;

        public AuthController(IConfiguration config, ApplicationDbContext context)
        {
            _config = config;
            _context = context;
        }

        [HttpPost("register")]
        public async Task<IActionResult> Register(RegisterDto dto)
        {
            if (await _context.Users.AnyAsync(u => u.Email == dto.Email))
                return BadRequest("Utilisateur déjà existant.");

            var secret = TwoFactorService.GenerateSecret();

            var user = new User
            {
                Email = dto.Email,
                PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
                TotpSecret = secret
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            var uri = TwoFactorService.GetQrCodeUri(dto.Email, secret);
            var imageBytes = TwoFactorService.GenerateQrCodeImage(uri);
            return File(imageBytes, "image/png");
        }

        [HttpPost("login")]
        public async Task<IActionResult> Login(LoginDto dto)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == dto.Email);
            if (user == null || !BCrypt.Net.BCrypt.Verify(dto.Password, user.PasswordHash))
                return Unauthorized("Email ou mot de passe incorrect");

            if (!TwoFactorService.ValidateCode(user.TotpSecret, dto.Code2FA))
                return Unauthorized("Code 2FA invalide");

            var token = GenerateJwtToken(user.Email);
            return Ok(new { token });
        }

        private string GenerateJwtToken(string email)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

            var claims = new[]
            {
                new Claim(ClaimTypes.Name, email)
            };

            var token = new JwtSecurityToken(
                claims: claims,
                expires: System.DateTime.Now.AddHours(1),
                signingCredentials: creds);

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    public record RegisterDto(string Email, string Password);
    public record LoginDto(string Email, string Password, string Code2FA);
}
