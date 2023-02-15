using AuthSrv.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace AuthSrv.Data;

public class AuthDbContext : IdentityDbContext<ZOrgUser>
{
  public AuthDbContext(DbContextOptions<AuthDbContext> options) : base(options)
  {

  }

  protected override void OnModelCreating(ModelBuilder builder)
  {
    base.OnModelCreating(builder);
    
    
  }
  
  public DbSet<ZOrgUser> Users { get; set; }
}