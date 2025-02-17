using Microsoft.EntityFrameworkCore;
using TuketAppAPI.Models;

namespace TuketAppAPI.Models
{
    public class TuketDbContext : DbContext
    {
        public TuketDbContext(DbContextOptions<TuketDbContext> options) : base(options) { }

        public DbSet<User> Users { get; set; }
        public DbSet<Business> Businesses { get; set; }

        protected override void OnModelCreating(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<User>().ToTable("users");
            modelBuilder.Entity<Business>().ToTable("businesses");
        }
    }
}