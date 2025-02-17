using System.ComponentModel.DataAnnotations;

namespace TuketAppAPI.Models
{
  public class User
{
    public int Id { get; set; }
    public string? Name { get; set; } // 🔥 Null atanabilir olarak işaretlendi
    public string? Email { get; set; }
    public string? Password { get; set; }
    public string Role { get; set; } = "consumer"; 
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;

}
}