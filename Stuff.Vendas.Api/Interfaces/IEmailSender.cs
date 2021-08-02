using System.Threading.Tasks;
using Stuff.Vendas.Api.ViewModels;

namespace Stuff.Vendas.Domain.Interfaces
{
    public interface IEmailSender
    {
        Task SendEmailAsync(string email, string subject, string message);
        Task Execute(string apiKey, string subject, string message, string email);
    }
}
