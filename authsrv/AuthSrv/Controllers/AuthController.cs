using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using AuthSrv.Models;
using AuthSrv.Models.DTO;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace AuthSrv.Controllers;

[Route("api/auth")]
[ApiController]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _configuration;
    private readonly RoleManager<IdentityRole> _roleManager;
    private readonly UserManager<ZOrgUser> _userManager;

    public AuthController(UserManager<ZOrgUser> userManager, RoleManager<IdentityRole> roleManager,
        IConfiguration configuration)
    {
        _userManager = userManager;
        _roleManager = roleManager;
        _configuration = configuration;
    }

    [HttpPost("login")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> Login([FromBody] LoginRequestDTO request)
    {
        var user = await _userManager.FindByNameAsync(request.Username);

        if (user is not null && await _userManager.CheckPasswordAsync(user, request.Password))
        {
            var token = await CreateJwtSecurityToken(user);

            return Ok(new
            {
                token = new JwtSecurityTokenHandler().WriteToken(token),
                expiration = token.ValidTo
            });
        }

        return Unauthorized();
    }

    private async Task<JwtSecurityToken> CreateJwtSecurityToken(ZOrgUser user)
    {
        var userRoles = await _userManager.GetRolesAsync(user);

        var authClaims = new List<Claim>
        {
            new(ClaimTypes.Name, user.UserName!),
            new(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };

        foreach (var userRole in userRoles) authClaims.Add(new Claim(ClaimTypes.Role, userRole));

        var authSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:Secret"]!));

        var token = new JwtSecurityToken(
            _configuration["JWT:ValidIssuer"],
            _configuration["JWT:ValidAudience"],
            expires: DateTime.Now.AddHours(3),
            claims: authClaims,
            signingCredentials: new SigningCredentials(authSigningKey, SecurityAlgorithms.HmacSha512)
        );
        return token;
    }

    [HttpPost("register")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    [ProducesResponseType(StatusCodes.Status403Forbidden)]
    public async Task<IActionResult> Register([FromBody] NewUserRequestDTO request)
    {
        if (!await _roleManager.RoleExistsAsync("Admin"))
        {
            await _roleManager.CreateAsync(new IdentityRole
            {
                Name = "Admin",
                NormalizedName = "ADMIN"
            });

            await _roleManager.CreateAsync(new IdentityRole
            {
                Name = "User",
                NormalizedName = "USER"
            });
        }

        if (await _userManager.FindByNameAsync(request.Username) is not null)
            return BadRequest(new
            {
                success = false,
                message = "A user with that name already exists"
            });

        if (await _userManager.FindByEmailAsync(request.Email) is not null)
            return BadRequest(new
            {
                success = false,
                message = "A user with that email already exists"
            });

        var newUser = new ZOrgUser
        {
            UserName = request.Username,
            Email = request.Email,
            SecurityStamp = Guid.NewGuid().ToString()
        };

        var result = await _userManager.CreateAsync(newUser, request.Password);

        if (!result.Succeeded)
            return StatusCode(StatusCodes.Status400BadRequest, new
            {
                success = false,
                message = "Unable to create new user"
            });

        await _userManager.AddToRolesAsync(newUser, request.Roles);

        return Ok(new
        {
            success = true,
            result = newUser
        });
    }

    [HttpGet("renew")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status419AuthenticationTimeout)]
    public async Task<IActionResult> RenewToken()
    {
        if (User.Identity?.Name is null) return Unauthorized();

        var user = await _userManager.FindByNameAsync(User.Identity.Name);

        if (user is null) return BadRequest();

        var token = await CreateJwtSecurityToken(user);

        return Ok(new
        {
            token = new JwtSecurityTokenHandler().WriteToken(token),
            expiration = token.ValidTo
        });
    }

    [HttpGet("user")]
    [Authorize(Roles = "Admin")]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> GetUsers()
    {
        var users = await _userManager.Users.ToListAsync();
        var result = new List<UserInformationDTO>();

        foreach (var user in users)
        {
            var userRoles = await _userManager.GetRolesAsync(user);
            result.Add(new UserInformationDTO
            {
                Email = user.Email ?? String.Empty,
                Username = user.UserName ?? String.Empty,
                Roles = userRoles.ToList()
            });
        }

        return Ok(result);
    }

    [HttpPost("user/pwreset")]
    [Authorize]
    [ProducesResponseType(StatusCodes.Status200OK)]
    [ProducesResponseType(StatusCodes.Status401Unauthorized)]
    public async Task<IActionResult> ResetPassword([FromBody] PasswordResetDTO dto)
    {
        if (User.Identity?.Name is null) return Unauthorized();

        var user = await _userManager.FindByNameAsync(User.Identity.Name);

        if (user is null) return BadRequest();

        var resetToken = await _userManager.GeneratePasswordResetTokenAsync(user);

        var result = await _userManager.ResetPasswordAsync(user, resetToken, dto.NewPassword);

        if (result.Succeeded) return Ok();

        return BadRequest();
    }
}