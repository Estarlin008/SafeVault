using NUnit.Framework;
using SafeVault.Utilities;
using SafeVault.Data;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        private UserRepository _repository = null!;

        [SetUp]
        public void Setup()
        {
            // Cadena de conexión de prueba (ajusta según tu entorno SQL Server)
            string connectionString = "Server=DESKTOP-B3MGHA9;Database=SafeVaultDB;Trusted_Connection=True;TrustServerCertificate=True;";
            _repository = new UserRepository(connectionString);
        }

        [Test]
        public void TestForSQLInjection()
        {   string maliciousInput = "'; DROP TABLE Users; --";
            string email = "sqltest@example.com";

            // Sanitizar antes de enviar
            string cleanUsername = InputSanitizer.Sanitize(maliciousInput);
            string cleanEmail = InputSanitizer.Sanitize(email);

            // Insertar usuario con entrada maliciosa
            _repository.AddUser(cleanUsername, cleanEmail, "TestPassword123");

            // Recuperar usuario para verificar que no se ejecutó código malicioso
            var user = _repository.GetUserByEmail(cleanEmail);

            Assert.NotNull(user, "El usuario debería existir, la tabla no debe haber sido eliminada.");
            Assert.That(user?.Username, Does.Not.Contain("DROP"), "El nombre no debe contener comandos SQL.");
        }

        [Test]
        public void TestForXSS()
        {
            string maliciousInput = "<script>alert('XSS');</script>";
            string email = "xsstest@example.com";

            string cleanUsername = InputSanitizer.Sanitize(maliciousInput);
            string cleanEmail = InputSanitizer.Sanitize(email);

            _repository.AddUser(cleanUsername, cleanEmail, "TestPassword123");
            var user = _repository.GetUserByEmail(cleanEmail);

            Assert.NotNull(user, "El usuario debería existir.");
            Assert.That(user?.Username, Does.Not.Contain("<script>"), "El nombre no debe contener etiquetas <script>.");
            Assert.That(user?.Username, Does.Not.Contain("alert"), "El nombre no debe contener código JavaScript.");

        }

        [Test]
        public void TestLoginWithInvalidPassword()
        {
            string email = "admin_test@example.com";

            _repository.AddUser("AdminUser", email, "AdminPassword123", "Admin");

            bool isAuthenticated = _repository.AuthenticateUser(email, "wrongpassword");

            Assert.IsFalse(isAuthenticated);
        }

        [Test]
        public void TestLoginWithNonExistentUser()
        {
            bool isAuthenticated = _repository.AuthenticateUser("ghost@example.com", "password");
            Assert.IsFalse(isAuthenticated, "El login debe fallar con usuario inexistente.");
        }

        [Test]
        public void TestAdminAccessAllowed()
        {
            string? role = _repository.GetUserRole("admin@example.com");
            Assert.AreEqual("Admin", role, "El usuario admin debe tener rol Admin.");
        }

         [Test]
        public void TestUserAccessDeniedToAdminPanel()
        {
            string? role = _repository.GetUserRole("user@example.com");
            Assert.AreEqual("User", role, "El usuario debe tener rol User.");
            Assert.AreNotEqual("Admin", role, "El usuario no debe tener acceso al panel de administración.");
        }

        [Test]
        public void TestEmailValidation()
        {
            bool isValid =
                InputSanitizer.IsValidEmail(
                    "correo-invalido"
                );

            Assert.IsFalse(
                isValid,
                "Debe rechazar emails inválidos."
            );
        }

        [Test]
        public void TestAdvancedSQLInjection()
        {
            string attack =
                "' UNION SELECT * FROM Users --";

            string sanitized =
                InputSanitizer.Sanitize(attack);

            Assert.That(
                sanitized,
                Does.Not.Contain("UNION")
            );

            Assert.That(
                sanitized,
                Does.Not.Contain("SELECT")
            );
        }


        [Test]
        public void TestAdvancedXSS()
        {
            string attack =
                "<img src=x onerror=alert('hack')>";

            string sanitized =
                InputSanitizer.Sanitize(attack);

            Assert.That(
                sanitized,
                Does.Not.Contain("alert")
            );

            Assert.That(
                sanitized,
                Does.Not.Contain("<img")
            );
        }
    }
}