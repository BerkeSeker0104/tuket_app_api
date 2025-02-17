using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using TuketAppAPI.Models;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using System.Text;

var builder = WebApplication.CreateBuilder(args);

//  Hangi yapılandırma dosyasının kullanıldığını terminale yaz
Console.WriteLine($"Using configuration file: {builder.Environment.EnvironmentName}");

//  MySQL Veritabanı Bağlantısını Yapılandır
var connectionString = builder.Configuration.GetConnectionString("DefaultConnection");
builder.Services.AddDbContext<TuketDbContext>(options =>
    options.UseMySql(connectionString, ServerVersion.AutoDetect(connectionString)));

//  JWT Authentication Ayarları
var jwtSettings = builder.Configuration.GetSection("JwtSettings");

//  Secret Key’in eksik olup olmadığını kontrol et
var secretKeyString = jwtSettings["Secret"];
if (string.IsNullOrEmpty(secretKeyString))
{
    throw new Exception(" Error: Secret Key is missing from configuration!");
}

//  Secret Key’i HEX olarak kullan
var secretKeyBytes = Encoding.UTF8.GetBytes(secretKeyString);
var secretKey = new SymmetricSecurityKey(secretKeyBytes);
Console.WriteLine($" Loaded Secret Key: {secretKeyString}");

//  Authentication & Authorization Middleware
builder.Services.AddAuthentication(options =>
{
    options.DefaultAuthenticateScheme = JwtBearerDefaults.AuthenticationScheme;
    options.DefaultChallengeScheme = JwtBearerDefaults.AuthenticationScheme;
})
.AddJwtBearer(options =>
{
    options.RequireHttpsMetadata = false;
    options.SaveToken = true;
    options.TokenValidationParameters = new TokenValidationParameters
    {
        ValidateIssuerSigningKey = true,
        IssuerSigningKey = secretKey,  //  HEX formatındaki Secret Key Kullanıldı
        ValidateIssuer = true,
        ValidateAudience = true,
        ValidIssuer = jwtSettings["Issuer"],
        ValidAudience = jwtSettings["Audience"],
        ValidateLifetime = true
    };
});

//  API Servislerini Ekleyelim
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

//  Swagger UI için JWT Desteğini Ekleyelim
builder.Services.AddSwaggerGen(options =>
{
    options.SwaggerDoc("v1", new OpenApiInfo { Title = "TuketAppAPI", Version = "v1" });

    // JWT Authentication için Swagger UI Konfigürasyonu
    options.AddSecurityDefinition("Bearer", new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "Bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Token'ınızı 'Bearer {token}' formatında girin."
    });

    options.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        {
            new OpenApiSecurityScheme
            {
                Reference = new OpenApiReference
                {
                    Type = ReferenceType.SecurityScheme,
                    Id = "Bearer"
                }
            },
            new string[] {}
        }
    });
});

//  Uygulamayı Başlat
var app = builder.Build();

//  Kullanılan ortamı terminale yaz
Console.WriteLine($" Application is running in {app.Environment.EnvironmentName} mode.");

//  Swagger UI'yi Aktif Et
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI();
}

//  Middleware'leri Aktif Et
app.UseHttpsRedirection();
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers(); 

app.Run();