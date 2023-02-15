namespace AuthSrv.Models.DTO;

public class LoginRequestDTO
{
  public string Username { get; set; } = String.Empty;
  public string Password { get; set; } = String.Empty;
}