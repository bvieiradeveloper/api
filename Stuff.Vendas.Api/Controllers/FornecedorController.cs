using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Stuff.Vendas.Api.Extensions;

namespace Stuff.Vendas.Api.Controllers
{
    [Authorize]
    [ApiController]
    [Route("[Controller]")]
    public class FornecedorController : ControllerBase
    {
        public FornecedorController()
        {
                
        }
        [CustomAuthorize("Fornecedor","Editar")]
        [HttpGet("atualizar")]
        public IActionResult AlualizarFornecedor()
        {
            return Ok("Fornecedor atualizado");
        }

        [CustomAuthorize("Fornecedor","remover")]
        [HttpDelete("deletar")]
        public IActionResult Deletar()
        {
            return Ok("Usuário removido");
        }
    }
}
