namespace identity.user;

using SendGrid;
using SendGrid.Helpers.Mail;

public class EmailSender : IEmailSender
{
  private readonly ILogger _logger;
  private readonly string key;

  public EmailSender(IConfiguration configuration, ILogger<EmailSender> logger)
  {
    key = configuration["SendGridKey"] ?? "";
    _logger = logger;
  }

  public async Task SendEmailAsync(string toEmail, string subject, string message)
  {
    if (string.IsNullOrEmpty(key))
    {
      throw new Exception("Null SendGridKey");
    }
    await Execute(key, subject, message, toEmail);
  }

  private async Task Execute(string apiKey, string subject, string message, string toEmail)
  {
    var client = new SendGridClient(apiKey);
    var msg = new SendGridMessage()
    {
      From = new EmailAddress("sender@psicologarichellysousa.com.br", ""),
      Subject = subject,
      PlainTextContent = message,
      HtmlContent = message
    };
    msg.AddTo(new EmailAddress(toEmail));

    msg.SetClickTracking(false, false);
    var response = await client.SendEmailAsync(msg);
    if (!response.IsSuccessStatusCode)
    {
      throw new Exception("Erro ao enviar e-mail!");
    }
    _logger.LogInformation(response.IsSuccessStatusCode ? $"Email to {toEmail} queued successfully!" : $"Failure Email to {toEmail}");
  }
}