using System;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Stuff.Vendas.Api.ViewModels;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.JsonWebTokens;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Text;
using Microsoft.AspNetCore.Authorization;

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
                return Ok(GerarJWT());
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

        private  string GerarJWT()
        {
            try
            {
                var tokenHandler = new JwtSecurityTokenHandler();
                var key = Encoding.ASCII.GetBytes(_appSettings.Secret);
                var token = tokenHandler.CreateToken(new SecurityTokenDescriptor
                {
                    Issuer = _appSettings.Emissor,
                    Audience = _appSettings.ValidoEm,
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
    }
}
