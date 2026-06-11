using SafeVault.Data;

var builder = WebApplication.CreateBuilder(args);

// Leer la cadena de conexión desde appsettings.json
string connectionString = builder.Configuration.GetConnectionString("DefaultConnection");

// Registrar el repositorio con la cadena de conexión
builder.Services.AddSingleton(new UserRepository(connectionString));

builder.Services.AddControllers();

var app = builder.Build();
app.MapControllers();
app.Run();