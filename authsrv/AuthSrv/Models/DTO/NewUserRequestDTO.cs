namespace AuthSrv.Models.DTO;

public class NewUserRequestDTO
{
  public string Username { get; set; } = String.Empty;
  public string Password { get; set; } = String.Empty;
  public string Email { get; set; } = String.Empty;
  public List<String> Roles { get; set; } = new();
}