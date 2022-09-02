using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Identity;
using Microsoft.EntityFrameworkCore;
using Web;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddControllersWithViews();
builder.Services.AddDbContext<DataContext>(o =>
{
    o.UseSqlServer(builder.Configuration.GetConnectionString("Data"));
});

builder.Services
            .AddIdentity<IdentityUser, IdentityRole>((options) => options.User.RequireUniqueEmail = false)
            .AddEntityFrameworkStores<DataContext>()
            .AddDefaultTokenProviders();

builder.Services.ConfigureApplicationCookie(options =>
{
    // Cookie settings
    options.Cookie.HttpOnly = true;
    options.ExpireTimeSpan = TimeSpan.FromMinutes(5);

    options.LoginPath = "/signin";
    options.AccessDeniedPath = "/accessdenied";
    options.LogoutPath = "/signout";
    options.SlidingExpiration = true;
});

builder.Services
    .AddAuthentication(authOptions =>
    {
        authOptions.DefaultAuthenticateScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    })    
    .AddCookie(cookieOptions =>
    {
        cookieOptions.LoginPath = "/signin";
        cookieOptions.LogoutPath = "/signout";
    })
    .AddDiscord(discordOptions =>
{
    discordOptions.ClientId = "";
    discordOptions.ClientSecret = "";
    discordOptions.Scope.Add("identify");

    discordOptions.SaveTokens = true;

    discordOptions.UserInformationEndpoint = "https://discordapp.com/api/users/@me";
    discordOptions.TokenEndpoint = "https://discordapp.com/api/oauth2/token";
    discordOptions.AuthorizationEndpoint = "https://discordapp.com/api/oauth2/authorize";
});

var app = builder.Build();

// Configure the HTTP request pipeline.
if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Home/Error");
    // The default HSTS value is 30 days. You may want to change this for production scenarios, see https://aka.ms/aspnetcore-hsts.
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseStaticFiles();

app.UseRouting();

app.UseAuthorization();
app.UseAuthentication();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}");

app.Run();
