using Microsoft.OpenApi.Models;

namespace identity.user;
public static class DocInitializer
{
  public static void InjectMySwagger(this IServiceCollection services)
  {
    services.AddSwaggerGen(options =>
        {
          options.AddSecurityDefinition(name: "Bearer", securityScheme: new OpenApiSecurityScheme
          {
            Name = "Authorization",
            Description = "Enter the Bearer Authorization string as following: `Bearer Generated-JWT-Token`",
            In = ParameterLocation.Header,
            Type = SecuritySchemeType.ApiKey,
            Scheme = "Bearer"
          });
          options.AddSecurityRequirement(new OpenApiSecurityRequirement
            {
            {
                new OpenApiSecurityScheme
                {
                    Name = "Bearer",
                    In = ParameterLocation.Header,
                    Reference = new OpenApiReference
                    {
                        Id = "Bearer",
                        Type = ReferenceType.SecurityScheme
                    }
                },
                new List<string>()
            }
            });
        });
  }

  public static void UseMyDocumentation(this IApplicationBuilder app)
  {
    app.UseSwagger();
    app.UseSwaggerUI();
  }
}