using System.Security.Claims;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace identity.user;

public class AuthorizationService : IAuthorizationService
{
  private readonly UserDbContext Context;

  public AuthorizationService(UserDbContext context)
  {
    Context = context;
  }

  public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, IEnumerable<IAuthorizationRequirement> requirements)
  {
    var idClaim = user.FindFirst(claim => claim.Type == "id")?.Value;
    var authTokenClaim = user.FindFirst(claim => claim.Type == "authToken")?.Value;
    if (authTokenClaim == null || idClaim == null)
    {
      return Task.FromResult(AuthorizationResult.Failed());
    }

    var listOfTokens = Context.AuthTokens?.Where(at => at.Value == authTokenClaim).Include(at => at.Users);

    if (listOfTokens.IsNullOrEmpty())
    {
      return Task.FromResult(AuthorizationResult.Failed());
    }

    AuthToken? authToken = listOfTokens?.First();

    if (authToken == null)
    {
      return Task.FromResult(AuthorizationResult.Failed());
    }

    if (authToken.Users.Exists(us => us.Id == idClaim))
    {
      return Task.FromResult(AuthorizationResult.Success());
    }

    return Task.FromResult(AuthorizationResult.Failed());
  }

  public Task<AuthorizationResult> AuthorizeAsync(ClaimsPrincipal user, object? resource, string policyName)
  {
    throw new NotImplementedException();
  }
}