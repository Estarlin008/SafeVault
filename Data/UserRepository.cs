// File: Data/UserRepository.cs
using System.Data.SqlClient;

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
        public void AddUser(string username, string email)
        {
            using (var connection = new SqlConnection(_connectionString))
            {
                string query = "INSERT INTO Users (Username, Email) VALUES (@Username, @Email)";

                using (var command = new SqlCommand(query, connection))
                {
                    command.Parameters.AddWithValue("@Username", username);
                    command.Parameters.AddWithValue("@Email", email);

                    connection.Open();
                    command.ExecuteNonQuery();
                }
            }
        }
    }
}