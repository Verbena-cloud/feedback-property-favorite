using Microsoft.AspNetCore.Http.Features;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.EntityFrameworkCore;
using MY_Message.Data;
using MY_Message.Services.Implements;
using MY_Message.Services.Interfaces;

namespace MY_Message
{
    public class Program
    {
        public static async Task Main(string[] args)
        {
            var builder = WebApplication.CreateBuilder(args);

            // Add services to the container.
            var connectionString = builder.Configuration.GetConnectionString("DefaultConnection") ?? throw new InvalidOperationException("Connection string 'DefaultConnection' not found.");
            builder.Services.AddDbContext<ApplicationDbContext>(options =>
                options.UseSqlServer(connectionString));
            builder.Services.AddDatabaseDeveloperPageExceptionFilter();

            // Configure file upload limits
            builder.Services.Configure<FormOptions>(options =>
            {
                options.MultipartBodyLengthLimit = 104857600; // 100 MB

            });

            builder.Services.AddIdentity<ApplicationUser, ApplicationRole>(
                options =>
                {
                    options.Password.RequireDigit = true;
                    options.Password.RequiredLength = 8;
                    options.Password.RequireNonAlphanumeric = true;
                    options.Password.RequireUppercase = true;
                    options.Password.RequireLowercase = true;

                }
                )
                .AddRoles<ApplicationRole>()
                .AddEntityFrameworkStores<ApplicationDbContext>()
                .AddDefaultTokenProviders();

            builder.Services.AddSignalR();
            builder.Services.AddRazorPages();
            builder.Services.AddControllersWithViews();
            builder.Services.AddSingleton<IEmailSender, EmailSender>();

            builder.Services.AddScoped<IEmailSender, EmailSender>();

            builder.Services.AddScoped<IFeedbackService, FeedbackService>();
            builder.Services.AddScoped<IPropertyService, PropertyService>();
            builder.Services.AddScoped<IFavouriteService, FavouriteService>();

            var app = builder.Build();

            // Seed roles and admin user
            using (var scope = app.Services.CreateScope())
            {
                var services = scope.ServiceProvider;

                // Seed roles
                var roleManager = scope.ServiceProvider.GetRequiredService<RoleManager<ApplicationRole>>();
                await SeedRolesAsync(roleManager);

                // Seed default admin user
                var userManager = scope.ServiceProvider.GetRequiredService<UserManager<ApplicationUser>>();
                await SeedAdminUserAsync(userManager);
            }

            // Configure the HTTP request pipeline
            if (app.Environment.IsDevelopment())
            {
                app.UseMigrationsEndPoint();
            }
            else
            {
                app.UseExceptionHandler("/Home/Error");
                app.UseHsts();
            }

            app.UseHttpsRedirection();
            app.UseStaticFiles();

            app.UseRouting();

            app.UseAuthentication();
            app.UseAuthorization();

            app.MapControllerRoute(
                name: "default",
                pattern: "{controller=Home}/{action=Index}/{id?}");
            app.MapRazorPages();
        }

        private static async Task SeedRolesAsync(RoleManager<ApplicationRole> roleManager)
        {
            var roles = new[] { "SuperAdmin", "Admin", "User" };

            foreach (var role in roles)
            {
                if (!await roleManager.RoleExistsAsync(role))
                {
                    var result = await roleManager.CreateAsync(new ApplicationRole { Name = role });
                    if (result.Succeeded)
                    {
                        Console.WriteLine($"Role '{role}' created successfully.");
                    }
                    else
                    {
                        Console.WriteLine($"Error creating role '{role}': {string.Join(", ", result.Errors.Select(e => e.Description))}");
                    }
                }
                else
                {
                    Console.WriteLine($"Role '{role}' already exists.");
                }
            }
        }

        private static async Task SeedAdminUserAsync(UserManager<ApplicationUser> userManager)
        {
            string email = "superadmin@admin.com";
            string password = "Testing123,";

            var user = await userManager.FindByEmailAsync(email);
            if (user == null)
            {
                user = new ApplicationUser
                {
                    UserName = email,
                    Email = email,
                    EmailConfirmed = true // Set to true to avoid email confirmation issues
                };

                var result = await userManager.CreateAsync(user, password);
                if (!result.Succeeded)
                {
                    //Console.WriteLine("Admin user created successfully.");
                    //await userManager.AddToRoleAsync(user, "SuperAdmin");
                    throw new Exception(string.Join(", ", result.Errors.Select(e => e.Description)));
                }
                else
                {
                    Console.WriteLine($"Error creating admin user: {string.Join(", ", result.Errors.Select(e => e.Description))}");
                }
            }
            else
            {
                Console.WriteLine("Admin user already exists.");
            }
        }

    }
}
