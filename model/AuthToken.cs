using System.ComponentModel.DataAnnotations;

namespace identity.user;

public class AuthToken
{
  [Key]
  public required Guid Id { get; set; }
  public required string Value { get; set; }
  public required long Expiration { get; set; }
  public List<User> Users { get; } = new();
  public required DateTime CreatedAt { get; set; }
}