using BasicAuth.Models;

namespace BasicAuth.Services
{
    public class UserService : IUserService
    {
        Task<User> IUserService.AuthenticateAsync(string username, string password)
        {
            User user = null;

            if("test".Equals(username) && "test123".Equals(password))
                user = new User()
                {
                    Id = "1",
                    Username = username
                };

            return Task.FromResult(user);
        }
    }
}
