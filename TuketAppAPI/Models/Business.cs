using System;
using System.ComponentModel.DataAnnotations;

namespace TuketAppAPI.Models
{
   public class Business
{
    public int Id { get; set; }
    public string? Name { get; set; } // 🔥 Null atanabilir
    public string? Address { get; set; } // 🔥 Null atanabilir
    public double Latitude { get; set; }
    public double Longitude { get; set; }
    public int UserId { get; set; }
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
}