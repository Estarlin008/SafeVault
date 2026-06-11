using NUnit.Framework;
using SafeVault.Utilities;
using SafeVault.Data;

namespace SafeVault.Tests
{
    [TestFixture]
    public class TestInputValidation
    {
        private UserRepository _repository;

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
            _repository.AddUser(cleanUsername, cleanEmail);

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

            _repository.AddUser(cleanUsername, cleanEmail);
            var user = _repository.GetUserByEmail(cleanEmail);

            Assert.NotNull(user, "El usuario debería existir.");
            Assert.That(user?.Username, Does.Not.Contain("<script>"), "El nombre no debe contener etiquetas <script>.");
            Assert.That(user?.Username, Does.Not.Contain("alert"), "El nombre no debe contener código JavaScript.");

        }
    }
}