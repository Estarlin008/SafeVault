

// File: Utilities/InputSanitizer.cs
using System.Text.RegularExpressions;

namespace SafeVault.Utilities
{
    public static class InputSanitizer
    {
        public static string Sanitize(string input)
        {
            if (string.IsNullOrWhiteSpace(input))
            return string.Empty;

            string sanitized = input;

            // 1. Eliminar etiquetas <script> completas con su contenido
            sanitized = Regex.Replace(sanitized, "<script.*?>.*?</script>", "", RegexOptions.IgnoreCase | RegexOptions.Singleline);

            // 2. Eliminar cualquier otra etiqueta HTML
            sanitized = Regex.Replace(sanitized, "<.*?>", string.Empty);

            // 3. Eliminar caracteres SQL peligrosos
            sanitized = sanitized.Replace("'", "")
                                .Replace("\"", "")
                                .Replace(";", "")
                                .Replace("--", "");

            // 4. Eliminar palabras clave peligrosas de SQL
            string[] sqlKeywords = { "DROP", "DELETE", "INSERT", "UPDATE", "ALTER" };
            foreach (var keyword in sqlKeywords)
            {   
                sanitized = Regex.Replace(sanitized, $@"\b{keyword}\b", "", RegexOptions.IgnoreCase);
            }

            // 5. Eliminar funciones de JavaScript comunes
            string[] jsKeywords = { "alert", "eval", "prompt" };
            foreach (var keyword in jsKeywords)
            {
                sanitized = Regex.Replace(sanitized, $@"\b{keyword}\b", "", RegexOptions.IgnoreCase);
            }


            // 6. Validar longitud máxima
            if (sanitized.Length > 100)
            {
                sanitized = sanitized.Substring(0, 100);
            }

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