using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace AuthServer.Repositories
{
    public interface IUserRepository
    {
        Task<int> GetUser(string username, string password);
    }
}
