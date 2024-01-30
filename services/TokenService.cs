using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.IdentityModel.Tokens;

namespace identity.user;

public class TokenService
{
  private readonly IConfiguration Configuration;
  private readonly UserDbContext Context;
  private static readonly int DAYS_TO_EXPIRE = 15;
  public TokenService(UserDbContext context, IConfiguration configuration)
  {
    Configuration = configuration;
    Context = context;
  }
  public string Generate(User user)
  {

    var authId = Guid.NewGuid();
    var value = authId.ToString();
    var expires = DateTime.Now.AddDays(DAYS_TO_EXPIRE);

    AuthToken authToken = new()
    {
      Id = authId,
      CreatedAt = DateTime.Now,
      Expiration = expires.Ticks,
      Value = value
    };

    authToken.Users.Add(user);
    Context.AuthTokens?.Add(authToken);
    Context.SaveChanges();

    var claims = new Claim[]
    {
        new("username", user.UserName ?? ""),
        new("id", user.Id),
        new("authToken", value),
        new("email", user.Email ?? "")
    };

    var chave = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["SymmetricSecurityKey"] ?? "0xa3fa6d97AaAz7e145b37451fc344e58c"));

    var signingCredentials = new SigningCredentials(chave, SecurityAlgorithms.HmacSha256);

    var token = new JwtSecurityToken
        (
        expires: expires,
        claims: claims,
        signingCredentials: signingCredentials
        );

    return new JwtSecurityTokenHandler().WriteToken(token);
  }

  public void RemoveAuthTokens(string[] authTokenValue)
  {
    AuthToken[]? authTokensFound = Context.AuthTokens?.Where(at => authTokenValue.Contains(at.Value)).ToArray();
    if (authTokensFound == null)
    {
      return;
    }
    Context.RemoveRange(authTokensFound);
    Context.SaveChanges();
  }
}