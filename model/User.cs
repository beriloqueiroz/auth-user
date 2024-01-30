namespace identity.user;

using Microsoft.AspNetCore.Identity;

public class User : IdentityUser
{
  public User() : base()
  {
  }

  public List<AuthToken> AuthTokens { get; } = new();
}