using AuthSrv.Models;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthSrv.Data;

public class AuthDbContext : IdentityDbContext<ZOrgUser>
{
  public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
  {

  }

  public DbSet<ZOrgUser> ZOrgUsers { get; set; } = null!;
}