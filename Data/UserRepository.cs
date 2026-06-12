// File: Data/UserRepository.cs
using System.Data.SqlClient;
using SafeVault.Utilities;
using BCrypt.Net;

namespace SafeVault.Data
{
    public class UserRepository
    {
        private readonly string _connectionString;

        public UserRepository(string connectionString)
        {
            _connectionString = connectionString;
        }

        // Recuperar información de usuario por email (ejemplo de login seguro)
        public (int UserId, string Username, string Email)? GetUserByEmail(string email)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "SELECT UserID, Username, Email FROM Users WHERE Email = @Email";

                using (var command = new SqlCommand(query, connection))
                {
                    // Parámetro seguro
                    command.Parameters.AddWithValue("@Email", email);

                    connection.Open();
                    using (var reader = command.ExecuteReader())
                    {
                        if (reader.Read())
                        {
                            return (
                                reader.GetInt32(0),   // UserID
                                reader.GetString(1),  // Username
                                reader.GetString(2)   // Email
                            );
                        }
                    }
                }
            }
            return null; // No encontrado
        }

        // Insertar usuario de forma segura
        public void AddUser(string username, string email, string password, string role = "User")
        {
            string cleanUsername = InputSanitizer.Sanitize(username);
            string cleanEmail = InputSanitizer.Sanitize(email);

            // Encriptar contraseña
            string passwordHash = BCrypt.Net.BCrypt.HashPassword(password);

            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "INSERT INTO Users (Username, Email, PasswordHash, Role) VALUES (@Username, @Email, @PasswordHash, @Role)";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", cleanUsername);
                    command.Parameters.AddWithValue("@Email", cleanEmail);
                    command.Parameters.AddWithValue("@PasswordHash", passwordHash);
                    command.Parameters.AddWithValue("@Role", role);

                    connection.Open();
                    command.ExecuteNonQuery();
                }
            }
        }

        // Autenticación: verificar credenciales
        public bool AuthenticateUser(string email, string password)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "SELECT PasswordHash FROM Users WHERE Email = @Email";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Email", email);
                    connection.Open();

                    var result = command.ExecuteScalar();
                    if (result == null) return false;

                    string storedHash = (string)result;
                    
                    if (string.IsNullOrWhiteSpace(storedHash))
                        return false;
                    return BCrypt.Net.BCrypt.Verify(password, storedHash);
                }
            }
        }


        // Obtener rol del usuario
        public string? GetUserRole(string email)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "SELECT Role FROM Users WHERE Email = @Email";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Email", email);
                    connection.Open();
                    return command.ExecuteScalar() as string;
                }
            }
        }

        public void UpdateUserRole(string email, string newRole)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "UPDATE Users SET Role = @Role WHERE Email = @Email";
                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Role", newRole);
                    command.Parameters.AddWithValue("@Email", email);

                    connection.Open();
                    command.ExecuteNonQuery();
                }
            }
        }
    }
}