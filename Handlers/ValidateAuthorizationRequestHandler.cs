using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using AuthServer.Configuration;
using Microsoft.AspNetCore;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.IdentityModel.Tokens;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthServer.Handlers
{
    public class ValidateAuthorizationRequestHandler : IOpenIddictServerHandler<OpenIddictServerEvents.ValidateAuthorizationRequestContext>
    {
        private readonly OpenIdConfiguration _configuration;
        public ValidateAuthorizationRequestHandler(OpenIdConfiguration configuration)
        {
            _configuration = configuration;
        }

        public ValueTask HandleAsync(OpenIddictServerEvents.ValidateAuthorizationRequestContext context)
        {
            var clients = _configuration.Clients;
            if (!clients.Contains(context.ClientId?.ToLower()))
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' doesn't match a registered client");
                return default;
            }

            var redirectUris = _configuration.RedirectUris;
            if (!redirectUris.Contains(context.RedirectUri?.ToLower()))
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    description:
                    "The specified 'redirect_uri' is not valid for this client application");
                return default;
            }

            return default;
        }
    }
}
