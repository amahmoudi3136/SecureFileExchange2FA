using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using SecureFileExchange2FA.Models;
using SecureFileExchange2FA.Services;

namespace SecureFileExchange2FA.Controllers;

[ApiController]
[Route("api/[controller]")]
public class AuthController : ControllerBase
{
    private static List<User> Users = new();
    private readonly IConfiguration _config;

    public AuthController(IConfiguration config)
    {
        _config = config;
    }

    [HttpPost("register")]
    public IActionResult Register(RegisterDto dto)
    {
        if (Users.Any(u => u.Email == dto.Email))
            return BadRequest("Utilisateur déjà existant.");

        var secret = TwoFactorService.GenerateSecret();

        var user = new User
        {
            Id = Users.Count + 1,
            Email = dto.Email,
            PasswordHash = BCrypt.Net.BCrypt.HashPassword(dto.Password),
            TotpSecret = secret
        };

        Users.Add(user);

        var uri = TwoFactorService.GetQrCodeUri(dto.Email, secret);
        var imageBytes = TwoFactorService.GenerateQrCodeImage(uri);
        return File(imageBytes, "image/png");
    }

    [HttpPost("login")]
    public IActionResult Login(LoginDto dto)
    {
        var user = Users.FirstOrDefault(u => u.Email == dto.Email);
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

        var token = new JwtSecurityToken(
            claims: new[] { new Claim(ClaimTypes.Name, email) },
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds
        );

        return new JwtSecurityTokenHandler().WriteToken(token);
    }
}
