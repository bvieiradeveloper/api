using SendGrid;
using SendGrid.Helpers.Mail;
using Stuff.Vendas.Api.Controllers;
using Stuff.Vendas.Domain.Interfaces;
using System.Threading.Tasks;
using Microsoft.Extensions.Options;

namespace Stuff.Vendas.Api.ViewModels
{
    public class EmailSender : IEmailSender
    {
        private readonly AuthMessageSenderOptions _authMessageSenderOptions;


        public EmailSender(IOptions<AuthMessageSenderOptions> authMessageSenderOptions)
        {
            _authMessageSenderOptions = authMessageSenderOptions.Value;
        }

        public Task Execute(string apiKey, string subject, string message, string email)
        {
            var client = new SendGridClient(apiKey);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("bruno.deveng@gmail.com", _authMessageSenderOptions.SendGridUser),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(email));


            msg.SetClickTracking(false, false);

            return client.SendEmailAsync(msg);
        }

        public Task SendEmailAsync(string email, string subject, string message)
        {
            return Execute(_authMessageSenderOptions.SendGridKey, subject, message, email);
        }
    }
}
