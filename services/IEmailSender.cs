namespace identity.user;

public interface IEmailSender
{
  Task SendEmailAsync(string toEmail, string subject, string message);
}