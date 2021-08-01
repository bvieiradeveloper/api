using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Stuff.Vendas.Api.ViewModels;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using JwtRegisteredClaimNames = Microsoft.IdentityModel.JsonWebTokens.JwtRegisteredClaimNames;

namespace Stuff.Vendas.Api.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly AppSettings _appSettings;
        public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager,IOptions<AppSettings> appSettings)
        {
            _userManager = userManager;
            _signInManager = signInManager;
            _appSettings = appSettings.Value;
        }

        [HttpPost("nova-conta")]
        public async Task<IActionResult> Registrar(RegisterViewModel registerViewModel)
        {
            if (!ModelState.IsValid) return BadRequest();

            var user = new IdentityUser()
            {
                UserName = registerViewModel.Email,
                Email = registerViewModel.Email,
                EmailConfirmed = true
            };

            var result = await _userManager.CreateAsync(user, registerViewModel.Password);
            if (result.Succeeded)
            {
                await _signInManager.SignInAsync(user, isPersistent: true);
                return Ok(GerarJWT(registerViewModel.Email));
            }

            return BadRequest(result.Errors);
        }
        [Authorize]
        [HttpPost("entrar")]
        public async Task<IActionResult> Entrar(LoginViewModel loginViewModel)
        {
            if (!ModelState.IsValid) return BadRequest();

            var result = await _signInManager.PasswordSignInAsync(loginViewModel.Email, loginViewModel.Password, false, true);

            if (result.Succeeded)
            {
                return Ok(loginViewModel);
            }

            if (result.IsLockedOut)
            {
                return Unauthorized("Usuário temporariamente bloqueado por tentativas inválidas");
            }
            return Unauthorized("Login e/ou senha inválidos");
        }

        private async Task<string> GerarJWT(string email)
        {
            try
            {
                var user = await _userManager.FindByEmailAsync(email);
                var claims = await _userManager.GetClaimsAsync(user);
                var roles = await _userManager.GetRolesAsync(user);

                claims.Add(new Claim(JwtRegisteredClaimNames.Sub, user.Id));
                claims.Add(new Claim(JwtRegisteredClaimNames.Email, user.Email));
                claims.Add(new Claim(JwtRegisteredClaimNames.Jti,Guid.NewGuid().ToString()));
                claims.Add(new Claim(JwtRegisteredClaimNames.Nbf,ToUnixEpochDate(DateTime.UtcNow).ToString()));
                claims.Add(new Claim(JwtRegisteredClaimNames.Iat, ToUnixEpochDate(DateTime.UtcNow).ToString(),ClaimValueTypes.Integer64));

                foreach (var userRole in roles)
                {
                    claims.Add(new Claim("role", userRole));
                }

                var identityClaims = new ClaimsIdentity();
                identityClaims.AddClaims(claims);

                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
                var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = _appSettings.Emissor,
                    Audience = _appSettings.ValidoEm,
                    Subject = identityClaims,
                    Expires = DateTime.UtcNow.AddHours(_appSettings.ExpiracaoHoras),
                    SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256Signature)
                });

                var encodedToken = tokenHandler.WriteToken(token);
                return encodedToken;
            }
            catch (Exception e)
            {
                Console.WriteLine(e);
                throw;
            }

        }
        private static long ToUnixEpochDate(DateTime date)
            => (long)Math.Round((date.ToUniversalTime() - new DateTimeOffset(1970, 1, 1, 0, 0, 0, TimeSpan.Zero)).TotalSeconds);
    }
}
