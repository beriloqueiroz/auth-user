using identity.user;

var builder = WebApplication.CreateBuilder(args);
var MyAllowSpecificOrigins = "_myAllowSpecificOrigins";

builder.Services.InjectIdentity(builder.Configuration);

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

builder.Services.InjectMySwagger();

builder.Services.AddCors(options =>
{
    options.AddPolicy(name: MyAllowSpecificOrigins,
                      policy =>
                      {
                          policy.WithOrigins("*");
                      });
});

var app = builder.Build();

Console.WriteLine("Setting environment variables for each target..., how production\n ");

if (app.Environment.IsDevelopment())
{
    app.UseMyDocumentation();
    Console.WriteLine("Setting environment variables for each target..., how development\n ");
    Environment.SetEnvironmentVariable("UrlBase", "http://localhost:3000");
    Environment.SetEnvironmentVariable("UrlConfirmUser", "/User/confirm");
}

app.UseHttpsRedirection();

if (app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/error-development");
}
else
{
    app.UseExceptionHandler("/error");
}

app.UseAuthentication();

app.UseAuthorization();

app.UseCors(MyAllowSpecificOrigins);

app.MapControllers();

app.Run();
