using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using MyProject.Models;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace MyProject.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly IConfiguration _config;
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        public AuthController(IConfiguration config, UserManager<IdentityUser> userManager, RoleManager<IdentityRole> roleManager)
        {
            _config = config;
            _userManager = userManager;
            _roleManager = roleManager;
        }

        [HttpPost("register")]
        public async Task<ActionResult> Register(User request)
        {
            var userExists = await _userManager.FindByNameAsync(request.UserName);
            if (userExists != null)
            { return StatusCode(StatusCodes.Status500InternalServerError, "User with this username already exists!"); }

            IdentityUser user = new()
            {
                Email = request.Email,
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = request.UserName
            };
            if (request.UserRole != "Admin" || request.UserRole != "User")
            { return StatusCode(StatusCodes.Status500InternalServerError, "Failed to create user, choose existing role such as \"Admin\" or \"User\"."); }

            var result = await _userManager.CreateAsync(user, request.Password);
            if (!result.Succeeded)
            { return StatusCode(StatusCodes.Status500InternalServerError, "Failed to create user, please try again."); }

            if (!await _roleManager.RoleExistsAsync(request.UserRole))
                await _roleManager.CreateAsync(new IdentityRole(request.UserRole));

            if (await _roleManager.RoleExistsAsync(request.UserRole))
            {
                await _userManager.AddToRoleAsync(user, request.UserRole);
            }

            return Ok("User created successfully.");
        }

        [HttpPost("login")]
        public async Task<ActionResult> LogIn(LoginRequest request)
        {   
            var user = await _userManager.FindByNameAsync(request.UserName);

            if (user is not null || await _userManager.CheckPasswordAsync(user, request.Password))
            {
                var userRoles = await _userManager.GetRolesAsync(user);

                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, user.UserName),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };

                foreach (var userRole in userRoles)
                {
                    authClaims.Add(new Claim(ClaimTypes.Role, userRole));
                }

                var token = GetToken(authClaims);

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token),
                    expiration = token.ValidTo
                });

            }
            return NotFound();
        }

        private JwtSecurityToken GetToken(List<Claim> authClaims)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var signIn = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var token = new JwtSecurityToken(
                _config["Jwt:Issuer"],
                _config["Jwt:Audience"],
                authClaims,
                expires: DateTime.UtcNow.AddMinutes(10),
                signingCredentials: signIn);

            return token;
        }
    }
}
