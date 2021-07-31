using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace Stuff.Vendas.Api.ViewModels
{
    public class RegisterViewModel
    {
        [EmailAddress(ErrorMessage = "{0} inválido.")]
        [Required(ErrorMessage = "{0} é obrigatório.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "{0} é obrigatório")]
        [StringLength(100,ErrorMessage = "O campo {0} deve estar entre {2} e {1}",MinimumLength = 6)]
        public string Password { get; set; }
        [Compare("Password",ErrorMessage = "As senhas não conferem")]
        public string ConfirmPassword { get; set; }
    }

    public class LoginViewModel
    {
        [EmailAddress(ErrorMessage = "{0} inválido.")]
        [Required(ErrorMessage = "{0} é obrigatório.")]
        public string Email { get; set; }
        [Required(ErrorMessage = "{0} é obrigatório")]
        [StringLength(100, ErrorMessage = "O campo {0} deve estar entre {2} e {1}", MinimumLength = 6)]
        public string Password { get; set; }
    }
}
