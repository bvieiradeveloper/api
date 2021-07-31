using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Stuff.Vendas.Api.ViewModels;
using System.Threading.Tasks;

namespace Stuff.Vendas.Api.Controllers
{
    [ApiController]
    [Route("[Controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        public AuthController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
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
                return Ok();
            }

            return BadRequest(result.Errors);
        }

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
    }
}
