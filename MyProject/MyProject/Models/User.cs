using System.ComponentModel.DataAnnotations;

namespace MyProject.Models
{
    public class User
    {
        [Required]
        public string UserName { get; set; }
        [EmailAddress]
        public string Email { get; set; }
        [Required]
        public string Password { get; set; }
        [Required]
        public string UserRole { get; set; }
    }
}
