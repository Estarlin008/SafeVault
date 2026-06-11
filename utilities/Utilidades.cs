

// File: Utilities/InputSanitizer.cs
using System.Text.RegularExpressions;

namespace SafeVault.Utilities
{
    public static class InputSanitizer
    {
        // Elimina etiquetas HTML y caracteres peligrosos
        public static string Sanitize(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
                return string.Empty;

            // 1. Eliminar etiquetas HTML (prevención XSS)
            string sanitized = Regex.Replace(input, "<.*?>", string.Empty);

            // 2. Eliminar caracteres SQL peligrosos
            sanitized = sanitized.Replace("'", "")
                                 .Replace("\"", "")
                                 .Replace(";", "")
                                 .Replace("--", "");
                                 // 3. Validar longitud máxima
            if (sanitized.Length > 100)
                sanitized = sanitized.Substring(0, 100);

            return sanitized.Trim();
        }

        // Validación de email con Regex
        public static bool IsValidEmail(string email)
        {
            if (string.IsNullOrWhiteSpace(email)) return false;

            string pattern = @"^[^@\s]+@[^@\s]+\.[^@\s]+$";
            return Regex.IsMatch(email, pattern);
        }
    }
}