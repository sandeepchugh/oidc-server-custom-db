using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Configuration
{
    public class OpenIdConfiguration
    {
        public List<string> Clients { get; set; }
        public List<string> RedirectUris { get; set; }
    }
}
