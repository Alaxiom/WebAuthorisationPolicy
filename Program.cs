using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authorization;
using System.Security.Claims;
using WebAuthorisationPolicy.PermissionHandlers;
using WebAuthorisationPolicy.PermissionRequirements;

var builder = WebApplication.CreateBuilder(args);

// Add services to the container.
builder.Services.AddSingleton<IAuthorizationMiddlewareResultHandler, RedirectAuthorizationMiddlewareResultHandler>();
// should this be transient?
// Don't register these as singletons if using EF
builder.Services.AddSingleton<IAuthorizationHandler, FunkyPermissionHandler>();


builder.Services.AddRazorPages();
builder.Services.AddControllersWithViews();

builder.Services.AddAuthorization(o =>
{
    o.AddPolicy("FunkyAuthPolicy", policy =>
    {
        policy.RequireAuthenticatedUser();
        policy.Requirements.Add(new NotBlockedAccessRequirement("FunkyApp", "blocked"));
        policy.Requirements.Add(new SiteAccessRequirement());
        policy.Requirements.Add(new ForcedLogoutRequirement());
    });
});
 
builder.Services.AddAuthentication(o =>
{
    o.DefaultScheme = CookieAuthenticationDefaults.AuthenticationScheme;
    o.RequireAuthenticatedSignIn = false;
}).AddCookie();

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


app.UseAuthentication();
app.UseAuthorization();

app.MapRazorPages();

app.MapControllerRoute(
    name: "default",
    pattern: "{controller=Home}/{action=Index}/{id?}")
    .RequireAuthorization("FunkyAuthPolicy");

// https://localhost:7170/Account/login?returnurl=/home

app.MapGet("/Account/Login", async (HttpContext ctx, string returnUrl) =>
{
    // allow sign in so we can actually run the policy
    await ctx.SignInAsync(new ClaimsPrincipal(new ClaimsIdentity(new[] { new Claim("alan", "test@test.com"), new Claim("site", "somesite") })));
    ctx.Response.Redirect(returnUrl);
});

app.Run();
