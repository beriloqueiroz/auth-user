namespace identity.user;

using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

public class UserDbContext : IdentityDbContext<User>
{
  public DbSet<AuthToken>? AuthTokens { get; set; }
  public UserDbContext(DbContextOptions<UserDbContext> options) : base(options)
  {
    AppContext.SetSwitch("Npgsql.EnableLegacyTimestampBehavior", true);//para solucionar datetime error Pgsql
  }
  protected override void OnModelCreating(ModelBuilder modelBuilder)
  {
    base.OnModelCreating(modelBuilder);
  }
}