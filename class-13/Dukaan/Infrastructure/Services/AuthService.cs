using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Dukaan.Domain.Interfaces;
using Dukaan.Infrastructure.Data.Model;
using Microsoft.AspNetCore.Identity;
using Microsoft.IdentityModel.Tokens;

namespace Dukaan.Infrastructure.Services;

public class AuthService : IAuthService
{
    private readonly UserManager<Merchant> _userManager;
    private readonly IConfiguration _configuration;

    public AuthService(UserManager<Merchant> userManager, IConfiguration configuration)
    {
        _userManager = userManager;
        _configuration = configuration;
    }

    public async Task<AuthResponseDto> LoginAsync(LoginRequestDto request)
    {
        var user = await _userManager.FindByEmailAsync(request.Email);

        if (user == null)
            throw new UnauthorizedAccessException("Invalid credentials");

        var isValid = await _userManager.CheckPasswordAsync(user, request.Password);

        if (!isValid)
            throw new UnauthorizedAccessException("Invalid credentials");

        return GenerateToken(user);
    }

    private AuthResponseDto GenerateToken(Merchant user)
    {
        var jwtSettings = _configuration.GetSection("Jwt");
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtSettings["Key"]!));
        var credentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
        var expiration = DateTime.UtcNow.AddMinutes(Convert.ToDouble(jwtSettings["DurationInMinutes"]));

        var claims = new[]
        {
            new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString()),
            new Claim(JwtRegisteredClaimNames.Email, user.Email!),
            new Claim("tenant_id", user.TenantId.ToString())
        };

        var token = new JwtSecurityToken(
            claims: claims,
            expires: expiration,
            signingCredentials: credentials
        );

        return new AuthResponseDto(
            Token: new JwtSecurityTokenHandler().WriteToken(token),
            Expiration: expiration
        );
    }
}