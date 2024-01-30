using System.Net;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Diagnostics;
using Microsoft.AspNetCore.Mvc;

namespace identity.user;

[ApiController]
[Route("[Controller]")]
public class UserController : ControllerBase
{

  private readonly UserService UserService;
  public readonly IAuthorizationService AuthorizationService;

  public UserController(UserService userService, IAuthorizationService authorizationService)
  {
    AuthorizationService = authorizationService;
    UserService = userService;
  }

  [HttpPost("register")]
  public async Task<IActionResult> RegisterUser(RegisterUserControllerDto input)
  {
    User user = new()
    {
      UserName = input.Username,
      Email = input.Email
    };

    await UserService.Register(user, input.Password);

    return Ok("Usuário criado com sucesso!");
  }

  [HttpPost("login")]
  public async Task<IActionResult> LoginUser(LoginUserControllerDto input)
  {
    var token = await UserService.Login(input.Username, input.Password);

    return Ok(token);
  }

  [HttpPost("login/email")]
  public async Task<IActionResult> LoginUserWithEmail(LoginEmailUserControllerDto input)
  {
    var token = await UserService.LoginWithEmail(input.Email, input.Password);

    return Ok(token);
  }

  [HttpGet("authorization")]
  [Authorize]
  public IActionResult IsAuthorized()
  {
    return Ok("Acesso permitido!");
  }

  [HttpGet("confirm")]
  public async Task<IActionResult> EmailConfirmationAsync(string id, string token)
  {
    await UserService.Confirm(id, token);
    return Ok("Usuário confirmado!");
  }

  [HttpGet("change-confirm")]
  public async Task<IActionResult> EmailChangeConfirmationAsync(string id, string token, string email)
  {
    await UserService.ChangeEmailConfirm(id, token, email);
    return Ok("Usuário confirmado!");
  }

  [HttpDelete("logout")]
  [Authorize]
  public async Task<IActionResult> Logout()
  {
    var authTokenClaim = User.FindFirst(claim => claim.Type == "authToken")?.Value;
    if (authTokenClaim == null)
    {
      return Ok();
    }
    await UserService.Logout(new[] { authTokenClaim });
    return Ok();
  }

  [HttpPut("change-password")]
  [Authorize]
  public async Task<IActionResult> ChangePassword(ChangePasswordControllerDto input)
  {
    var id = User.FindFirst(claim => claim.Type == "id")?.Value;
    if (id == null)
    {
      return NotFound();
    }
    var username = User.FindFirst(claim => claim.Type == "username")?.Value;
    if (username == null)
    {
      return NotFound();
    }
    await UserService.ChangePassword(id, input.NewPassword, input.OldPassword);
    return Ok();
  }

  [HttpPut("change-email")]
  [Authorize]
  public async Task<IActionResult> ChangeEmail(string email)
  {
    var userId = User.FindFirst(claim => claim.Type == "id")?.Value;
    if (userId == null)
    {
      return NotFound();
    }
    await UserService.ChangeEmail(userId, email);
    return Ok();
  }

  [HttpPut("forgot-password")]
  public async Task<IActionResult> ForgotPassword(string email)
  {
    await UserService.ForgotPassword(email);
    return Ok();
  }

  [Route("/error-development")]
  [ApiExplorerSettings(IgnoreApi = true)]
  public IActionResult HandleErrorDevelopment([FromServices] IHostEnvironment hostEnvironment)
  {
    if (!hostEnvironment.IsDevelopment())
    {
      return NotFound();
    }

    var exceptionHandlerFeature = HttpContext.Features.Get<IExceptionHandlerFeature>()!;

    return FilterException(exceptionHandlerFeature.Error);
  }

  [Route("/error")]
  [ApiExplorerSettings(IgnoreApi = true)]
  public IActionResult HandleError() => Problem();


  private IActionResult FilterException(Exception exception)
  {
    HttpStatusCode code;
    switch (exception)
    {
      case KeyNotFoundException
            or FileNotFoundException:
        code = HttpStatusCode.NotFound;
        break;
      case UnauthorizedAccessException:
        code = HttpStatusCode.Unauthorized;
        break;
      default:
        code = HttpStatusCode.InternalServerError;
        break;
    }
    return Problem(
        detail: exception.StackTrace,
        title: exception.Message,
        statusCode: (int?)code
        );
  }

}
