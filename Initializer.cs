
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;

namespace identity.user;

public static class Initializer
{
  public static void InjectIdentity(this IServiceCollection services, IConfiguration Configuration)
  {
    services.AddDbContext<UserDbContext>(options => options.UseNpgsql(Configuration["ConnectionStrings:UserConnection"]));

    services.AddIdentity<User, IdentityRole>(options =>
    {
      options.SignIn.RequireConfirmedAccount = true;
      options.Lockout.MaxFailedAccessAttempts = 3;
      options.Lockout.DefaultLockoutTimeSpan = TimeSpan.FromMinutes(5);
    })
    .AddEntityFrameworkStores<UserDbContext>()
    .AddDefaultTokenProviders();

    services.AddRazorPages();

    services.AddAuthentication(options =>
    {
      options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
      options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
    }).AddJwtBearer(options =>
    {
      options.TokenValidationParameters = new()
      {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Configuration["SymmetricSecurityKey"] ?? "")),
        ValidateAudience = false,
        ValidateIssuer = false,
        ClockSkew = TimeSpan.Zero,
      };
    });

    services.AddScoped<UserService>();
    services.AddScoped<TokenService>();
    services.AddScoped<IAuthorizationService, AuthorizationService>();

    services.AddTransient<IEmailSender, EmailSender>();

    var db = services.BuildServiceProvider().GetRequiredService<UserDbContext>();
    db.Database.CanConnectAsync().ContinueWith(_ => db.Database.Migrate());

  }
}