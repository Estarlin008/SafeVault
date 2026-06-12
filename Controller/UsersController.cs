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
        public IActionResult Register(string username, string email, string password, string role = "User")
        {
            if (!InputSanitizer.IsValidEmail(email))
                return BadRequest("Email inválido.");

            _repository.AddUser(username, email, password, role);
            return Ok("Usuario registrado de forma segura.");
        }

        [HttpPost("login")]
        public IActionResult Login(string email, string password)
        {
            bool isAuthenticated = _repository.AuthenticateUser(email, password);
            if (!isAuthenticated)
                return Unauthorized("Credenciales inválidas.");

            string? role = _repository.GetUserRole(email);
            return Ok(new { Message = "Login exitoso", Role = role });
        }


        [HttpGet("admin-tools")]
        public IActionResult AdminTools(string email)
        {
            string? role = _repository.GetUserRole(email);
            if (role != "Admin")
                return Unauthorized("Acceso restringido a administradores.");

            return Ok("Herramientas administrativas disponibles.");
        }

        [HttpGet("admin-panel")]
        public IActionResult AdminPanel(string email)
        {
            string? role = _repository.GetUserRole(email);
            if (role != "Admin")
                return Unauthorized("Acceso restringido a administradores.");

            return Ok("Bienvenido al panel de administración.");
        }

        [HttpGet("user-dashboard")]
        public IActionResult UserDashboard(string email)
        {
            string? role = _repository.GetUserRole(email);
            if (role != "User" && role != "Admin")
                return Unauthorized("Acceso restringido a usuarios registrados.");

            return Ok("Bienvenido al dashboard de usuario.");
        }
    }
}