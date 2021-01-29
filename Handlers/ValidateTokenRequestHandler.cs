using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using AuthServer.Configuration;
using OpenIddict.Abstractions;
using OpenIddict.Server;

namespace AuthServer.Handlers
{
    public class ValidateTokenRequestHandler: IOpenIddictServerHandler<OpenIddictServerEvents.ValidateTokenRequestContext>
    {
        private readonly OpenIdConfiguration _configuration;
        public ValidateTokenRequestHandler(OpenIdConfiguration configuration)
        {
            _configuration = configuration;
        }

        public ValueTask HandleAsync(OpenIddictServerEvents.ValidateTokenRequestContext context)
        {
            var clients = _configuration.Clients;
            if (!clients.Contains(context.ClientId?.ToLower()))
            {
                context.Reject(error: OpenIddictConstants.Errors.InvalidClient,
                    description: "The specified 'client_id' doesn't match a registered client");
                return default;
            }

            // This demo is used by a single client application and no client secret validation is performed
            return default;
        }
    }
}
