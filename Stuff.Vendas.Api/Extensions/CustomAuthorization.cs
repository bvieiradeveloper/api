using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;
using Microsoft.AspNetCore.Mvc.Filters;

namespace Stuff.Vendas.Api.Extensions
{
    public class CustomAuthorization
    {
        public static bool ValidarClaimsUsuario(HttpContext context, string claimName, string claimValue)
        {
            return context.User.Identity.IsAuthenticated && context.User.Claims.Any(c=>c.Type == claimName && c.Value.Contains(claimValue));
        }
    }

    public class CustomAuthorizeAttribute : TypeFilterAttribute
    {
        public CustomAuthorizeAttribute(string claimName, string claimValue) : base(typeof(RequisitoCLaimFilter))
        {
            Arguments = new object[] {new Claim(claimName, claimValue)};
        }
    }

    public class RequisitoCLaimFilter : IAuthorizationFilter
    {
        private readonly Claim _claim;

        public RequisitoCLaimFilter(Claim claim)
        {
            _claim = claim;
        }
        public void OnAuthorization(AuthorizationFilterContext context)
        {
            if (!context.HttpContext.User.Identity.IsAuthenticated)
            {
                context.Result = new StatusCodeResult(401);
                return;
            }

            if (CustomAuthorization.ValidarClaimsUsuario(context.HttpContext, _claim.Type, _claim.Value))
            {
                context.Result = new StatusCodeResult(403);
            }
        }

    }
}
