using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Security.Principal;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Builder;
using Microsoft.AspNetCore.Hosting;
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
            services.AddControllers();

            services.AddAuthentication()
                .AddCookie();

            services.AddOpenIddict()
                .AddServer(options =>
                {
                    options.AddDevelopmentEncryptionCertificate()
                        .AddDevelopmentSigningCertificate();

                    options.AllowAuthorizationCodeFlow();

                    options.SetAuthorizationEndpointUris("/connect/authorize")
                        .SetTokenEndpointUris("/connect/token");

                    options.EnableDegradedMode();

                    options.UseAspNetCore();

                    options.AddEventHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>(builder =>
                    {
                        builder.UseInlineHandler(context =>
                        {
                            if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal))
                            {
                                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                                    description:"The specified 'client_id' doesn't match a registered client");
                                return default;
                            }
                            
                            if (!string.Equals(context.RedirectUri, "http://localhost:3000", StringComparison.Ordinal))
                            {
                                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                                    description:"The specified 'redirect_uri' is not valid for this client application");
                                return default;
                            }

                            return default;
                        });
                    });

                    options.AddEventHandler<OpenIddictServerEvents.ValidateTokenRequestContext>(builder =>
                    {
                        builder.UseInlineHandler(context =>
                        {
                            if (!string.Equals(context.ClientId, "console_app", StringComparison.Ordinal))
                            {
                                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                                    description: "The specified 'client_id' doesn't match a registered client");
                                return default;
                            }
                            
                            // This demo is used by a single client application and no client secret validation is performed
                            return default;
                        });
                    });

                    options.AddEventHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>(builder =>
                    {
                        builder.UseInlineHandler( async context =>
                        {
                            var request = context.Transaction.GetHttpRequest() ??
                                          throw new InvalidOperationException(
                                              "The ASP.NET Core request cannot be retrieved");
                            
                            // TODO: validate against database
                            var principal = new ClaimsPrincipal(new ClaimsIdentity(new GenericIdentity("TestUser")));
                            await Task.CompletedTask;
                            
                            if (principal == null)
                            {
                                context.HandleRequest();
                                return;
                            }
                            
                            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
                            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject,
                                principal.GetClaim(ClaimTypes.NameIdentifier)));

                            foreach (var claim in identity.Claims)
                            {
                                claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
                            }
                            
                            context.Principal = new ClaimsPrincipal(identity);
                        });
                    });
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

            app.UseEndpoints(endpoints => { endpoints.MapControllers(); });
        }
    }
}