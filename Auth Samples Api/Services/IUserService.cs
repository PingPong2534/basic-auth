using BasicAuth.Models;

namespace BasicAuth.Services
{
    public interface IUserService
    {
        Task<User> AuthenticateAsync(string username, string password);
    }
}
