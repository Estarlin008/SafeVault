// File: Controllers/UsersController.cs
using Microsoft.AspNetCore.Mvc;
using SafeVault.Data;
using SafeVault.Utilities; // Para InputSanitizer

namespace SafeVault.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class UsersController : ControllerBase
    {
        private readonly UserRepository _repository;

        public UsersController(IConfiguration config)
        {
            string connectionString = config.GetConnectionString("DefaultConnection");
            _repository = new UserRepository(connectionString);
        }

        [HttpPost("register")]
        public IActionResult Register(string username, string email)
        {
            // Sanitizar entradas
            string cleanUsername = InputSanitizer.Sanitize(username);
            string cleanEmail = InputSanitizer.Sanitize(email);

            if (!InputSanitizer.IsValidEmail(cleanEmail))
                return BadRequest("Email inválido.");

            _repository.AddUser(cleanUsername, cleanEmail);
            return Ok("Usuario registrado de forma segura.");
        }

        [HttpGet("login")]
        public IActionResult Login(string email)
        {
            var user = _repository.GetUserByEmail(email);
            if (user == null)
                return NotFound("Usuario no encontrado.");

            return Ok(user);
        }
    }
}