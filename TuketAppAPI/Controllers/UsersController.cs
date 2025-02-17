using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.AspNetCore.Authorization;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using TuketAppAPI.Models;

namespace TuketAppAPI.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly TuketDbContext _context;
        private readonly IConfiguration _configuration;

        public UsersController(TuketDbContext context, IConfiguration configuration)
        {
            _context = context;
            _configuration = configuration;
        }

        // ✅ Kullanıcı Kayıt (Register)
        [HttpPost("register")]
        public async Task<IActionResult> Register([FromBody] UserRegisterRequest request)
        {
            if (await _context.Users.AnyAsync(u => u.Email == request.Email))
            {
                return BadRequest("Bu e-posta zaten kayıtlı.");
            }

            var user = new User
            {
                Name = request.Name,
                Email = request.Email,
                Password = HashPassword(request.Password),
                Role = "consumer",
                CreatedAt = DateTime.UtcNow
            };

            _context.Users.Add(user);
            await _context.SaveChangesAsync();

            return Ok("Kullanıcı başarıyla oluşturuldu.");
        }

        // ✅ Kullanıcı Girişi (Login) + JWT Token
        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] UserLoginRequest request)
        {
            var user = await _context.Users.FirstOrDefaultAsync(u => u.Email == request.Email);
            if (user == null || user.Password != HashPassword(request.Password))
            {
                return Unauthorized("Geçersiz e-posta veya şifre.");
            }

            var token = GenerateJwtToken(user);
            return Ok(new { message = "Giriş başarılı", token });
        }

        // ✅ Kullanıcı Bilgilerini Getiren Endpoint
        [HttpGet("me")]
        [Authorize]  // Sadece giriş yapmış kullanıcılar erişebilir
        public async Task<IActionResult> GetUserProfile()
        {
            var userId = User.FindFirstValue(ClaimTypes.NameIdentifier); // Token'dan kullanıcı ID'sini al
            if (userId == null)
            {
                return Unauthorized(new { message = "Yetkilendirme başarısız." });
            }

            var user = await _context.Users.FindAsync(int.Parse(userId));
            if (user == null)
            {
                return NotFound(new { message = "Kullanıcı bulunamadı." });
            }

            return Ok(new
            {
                id = user.Id,
                name = user.Name,
                email = user.Email,
                role = user.Role
            });
        }

        // ✅ Şifreyi Hashleme
        private string HashPassword(string password)
        {
            using var sha256 = SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return BitConverter.ToString(hashedBytes).Replace("-", "").ToLower();
        }

        // ✅ JWT Token Oluşturma Fonksiyonu
        private string GenerateJwtToken(User user)
        {
            var jwtSettings = _configuration.GetSection("JwtSettings");
            var secretKeyString = jwtSettings["Secret"];

            if (string.IsNullOrEmpty(secretKeyString))
            {
                throw new Exception("🚨 Secret Key is missing!");
            }

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(secretKeyString));
            var claims = new[]
            {
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
                new Claim(JwtRegisteredClaimNames.Email, user.Email),
                new Claim(ClaimTypes.NameIdentifier, user.Id.ToString()),
                new Claim(ClaimTypes.Role, user.Role)
            };

            var token = new JwtSecurityToken(
                issuer: jwtSettings["Issuer"],
                audience: jwtSettings["Audience"],
                claims: claims,
                expires: DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["ExpiryMinutes"])),
                signingCredentials: new SigningCredentials(key, SecurityAlgorithms.HmacSha256)
            );

            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }

    // Kullanıcı kayıt isteği için model
    public class UserRegisterRequest
    {
        public string Name { get; set; }
        public string Email { get; set; }
        public string Password { get; set; }
    }

    // Kullanıcı giriş isteği için model
    public class UserLoginRequest
    {
        public string Email { get; set; }
        public string Password { get; set; }
    }
}