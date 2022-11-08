using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace MyProject.DbContext
{
    public class MyProjectDbContext : IdentityDbContext<IdentityUser>
    {
        public MyProjectDbContext(DbContextOptions<MyProjectDbContext> options)
            : base(options)
        {

        }
    }
}
