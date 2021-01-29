using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthServer.Handlers
{
    public class HandleAuthorizationRequestHandler : IOpenIddictServerHandler<OpenIddictServerEvents.HandleAuthorizationRequestContext>
    {
        public async ValueTask HandleAsync(OpenIddictServerEvents.HandleAuthorizationRequestContext context)
        {
            var request = context.Transaction.GetHttpRequest() ??
                                  throw new InvalidOperationException(
                                      "The ASP.NET Core request cannot be retrieved");

            var principal = (await request.HttpContext.AuthenticateAsync(CookieAuthenticationDefaults.AuthenticationScheme))?.Principal;
            if (principal == null)
            {
                await request.HttpContext.ChallengeAsync(CookieAuthenticationDefaults.AuthenticationScheme);
                context.HandleRequest();
                return;
            }

            var identity = new ClaimsIdentity(TokenValidationParameters.DefaultAuthenticationType);
            identity.AddClaim(new Claim(OpenIddictConstants.Claims.Subject,
                principal.GetClaim(ClaimTypes.Name)));

            foreach (var claim in identity.Claims)
            {
                claim.SetDestinations(OpenIddictConstants.Destinations.AccessToken);
            }

            context.Principal = new ClaimsPrincipal(identity);
        }
    }
}
