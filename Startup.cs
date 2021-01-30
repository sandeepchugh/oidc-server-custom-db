using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using AuthServer.Configuration;
using AuthServer.Handlers;
using AuthServer.Repositories;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
using Microsoft.AspNetCore.HttpOverrides;
using Microsoft.AspNetCore.HttpsPolicy;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Hosting;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthServer
{
    public class Startup
    {
        public Startup(IConfiguration configuration)
        {
            Configuration = configuration;
        }

        public IConfiguration Configuration { get; }

        // This method gets called by the runtime. Use this method to add services to the container.
        public void ConfigureServices(IServiceCollection services)
        {
            services.AddControllersWithViews();
            string connectionString = Configuration.GetConnectionString("DefaultConnection");
            services.AddScoped<IUserRepository>(x => new UserRepository(connectionString));

            services.AddSingleton(Configuration.GetSection("OpenId").Get<OpenIdConfiguration>());

            //services.AddSingleton<IConfiguration>(Configuration);
            services.AddAuthentication(CookieAuthenticationDefaults.AuthenticationScheme)
                .AddCookie(CookieAuthenticationDefaults.AuthenticationScheme,
                    options => { options.LoginPath = "/account/login"; });

            services.Configure<ForwardedHeadersOptions>(options =>
            {
                options.ForwardedHeaders = ForwardedHeaders.XForwardedProto;
            });
            
            services.AddOpenIddict()
                .AddServer(options =>
                {
                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();

                    
                    // Encryption and signing of tokens
                    // options
                    //     .AddEphemeralEncryptionKey()
                    //     .AddEphemeralSigningKey();

                    options
                        .AllowAuthorizationCodeFlow()
                        .RequireProofKeyForCodeExchange()
                        .AllowClientCredentialsFlow()
                        .AllowPasswordFlow()
                        .AllowImplicitFlow()
                        .AllowRefreshTokenFlow();

                    // Mark the "email", "profile" and "roles" scopes as supported scopes.
                    options.RegisterScopes(OpenIddictConstants.Scopes.Email,
                        OpenIddictConstants.Scopes.Profile,
                        OpenIddictConstants.Scopes.Roles);

                    options
                        .SetAuthorizationEndpointUris("/connect/authorize")
                        .SetTokenEndpointUris("/connect/token")
                        .SetUserinfoEndpointUris("/connect/userinfo");

                    // Disables encryption of token
                    options.DisableAccessTokenEncryption();

                    // Register scopes (permissions)
                    options.RegisterScopes("api");

                    options.EnableDegradedMode();

                    options.UseAspNetCore()
                        .EnableTokenEndpointPassthrough()
                        .EnableAuthorizationEndpointPassthrough()
                        .EnableUserinfoEndpointPassthrough();

                    options.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(builder =>
                        builder.UseScopedHandler<ValidateAuthorizationRequestHandler>());

                    options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(builder =>
                        builder.UseScopedHandler<ValidateTokenRequestHandler>());

                    options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(builder =>
                        builder.UseScopedHandler<HandleAuthorizationRequestHandler>());

                    //options.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(builder =>
                    //{
                    //    builder.UseInlineHandler(context =>
                    //    {
                    //        var clients = new List<string> {"console_app"};
                    //        if (!clients.Contains(context.ClientId?.ToLower()))
                    //        {
                    //            context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    //                description: "The specified 'client_id' doesn't match a registered client");
                    //            return default;
                    //        }

                    //        var redirectUris = new List<string>
                    //            {"https://localhost:3000", "https://oauth.pstmn.io/v1/callback"};
                    //        if (!redirectUris.Contains(context.RedirectUri?.ToLower()))
                    //        {
                    //            context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    //                description:
                    //                "The specified 'redirect_uri' is not valid for this client application");
                    //            return default;
                    //        }

                    //        return default;
                    //    });
                    //});


                    //options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(builder =>
                    //{
                    //    builder.UseInlineHandler(context =>
                    //    {
                    //        var clients = new List<string> {"console_app"};
                    //        if (!clients.Contains(context.ClientId?.ToLower()))
                    //        {
                    //            context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    //                description: "The specified 'client_id' doesn't match a registered client");
                    //            return default;
                    //        }

                    //        // This demo is used by a single client application and no client secret validation is performed
                    //        return default;
                    //    });
                    //});

                    //options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(builder =>
                    //{
                    //    builder.UseInlineHandler( async context =>
                    //    {
                    //        var request = context.Transaction.GetHttpRequest() ??
                    //                      throw new InvalidOperationException(
                    //                          "The ASP.NET Core request cannot be retrieved");

                    //        var principal = (await request.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme))?.Principal;
                    //        if (principal == null)
                    //        {
                    //            await request.HttpContext.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                    //            context.HandleRequest();
                    //            return;
                    //        }

                    //        var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                    //        identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject,
                    //            principal.GetClaim(ClaimTypes.Name)));

                    //        foreach (var claim in identity.Claims)
                    //        {
                    //            claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                    //        }

                    //        context.Principal = new ClaimsPrincipal(identity);
                    //    });
                    //});
                })
                .AddValidation(options =>
                {
                    options.UseLocalServer();
                    options.UseAspNetCore();
                });
    
    }

        // This method gets called by the runtime. Use this method to configure the HTTP request pipeline.
        public void Configure(IApplicationBuilder app, IWebHostEnvironment env)
        {
            if (env.IsDevelopment())
            {
                app.UseDeveloperExceptionPage();
            }

            app.UseHttpsRedirection();

            app.UseRouting();

            app.UseAuthentication();
            
            app.UseAuthorization();

            app.UseEndpoints(endpoints => { endpoints.MapDefaultControllerRoute(); });
        }
    }
}