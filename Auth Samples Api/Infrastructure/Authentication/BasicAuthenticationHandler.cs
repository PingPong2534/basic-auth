using BasicAuth.Models;
using BasicAuth.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc.Controllers;
using Microsoft.Extensions.Options;
using System.Net.Http.Headers;
using System.Reflection;
using System.Security.Claims;
using System.Text;
using System.Text.Encodings.Web;

namespace BasicAuth.Infrastructure.Authentication
{
    public class BasicAuthenticationHandler : AuthenticationHandler<AuthenticationSchemeOptions>
    {
        private readonly IUserService _userService;

        public BasicAuthenticationHandler(
            IOptionsMonitor<AuthenticationSchemeOptions> options,
            ILoggerFactory logger,
            UrlEncoder encoder,
            ISystemClock clock,
            IUserService userService)
            : base(options, logger, encoder, clock)
        {
            _userService = userService;
        }

        protected override async Task<AuthenticateResult> HandleAuthenticateAsync()
        {
            User user;

            try
            {
                var actionDescriptor = Context.GetEndpoint()?.Metadata.GetMetadata<ControllerActionDescriptor>();
                if (actionDescriptor == null)
                    return AuthenticateResult.NoResult();

                var controllerType = actionDescriptor.ControllerTypeInfo.AsType();
                var methodInfo = actionDescriptor.MethodInfo;

                var isAutherize = controllerType.GetCustomAttribute(typeof(AuthorizeAttribute)) != null;
                if (!isAutherize)
                    return AuthenticateResult.NoResult();

                var isAllowAnonymous = methodInfo.GetCustomAttribute(typeof(AllowAnonymousAttribute)) != null;
                if (isAllowAnonymous)
                    return AuthenticateResult.NoResult();

                var authHeader = AuthenticationHeaderValue.Parse(Request.Headers["Authorization"]);
                var credentialBytes = Convert.FromBase64String(authHeader.Parameter);
                var credentials = Encoding.UTF8.GetString(credentialBytes).Split(new[] { ':' }, 2);
                var username = credentials[0];
                var password = credentials[1];
                user = await _userService.AuthenticateAsync(username, password);
            }
            catch
            {
                return AuthenticateResult.Fail("Error Occured.Authorization failed.");
            }

            if (user == null)
                return AuthenticateResult.Fail("Invalid Credentials");

            var claims = new[]
            {
                new Claim(ClaimTypes.NameIdentifier, user.Id),
                new Claim(ClaimTypes.Name, user.Username),
            };

            var identity = new ClaimsIdentity(claims, Scheme.Name);
            var principal = new ClaimsPrincipal(identity);

            var ticket = new AuthenticationTicket(principal, Scheme.Name);

            return AuthenticateResult.Success(ticket);
        }
    }
}