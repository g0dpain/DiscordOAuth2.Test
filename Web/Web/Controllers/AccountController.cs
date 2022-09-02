using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Web.Extensions;

namespace Web.Controllers
{
    public class AccountController : Controller
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly SignInManager<IdentityUser> _signInManager;


        public AccountController(UserManager<IdentityUser> userManager, SignInManager<IdentityUser> signInManager)
        {
            _userManager = userManager;
            _signInManager = signInManager;
        }

        public IActionResult Index()
        {
            return RedirectToAction(nameof(Login));
        }


        [Route("~/signin")]
        public async Task<IActionResult> Login() => View(await HttpContext.GetExternalProvidersAsync());


        [HttpPost("~/signin")]
        public async Task<IActionResult> Index([FromForm] string provider)
        {
            // Note: the "provider" parameter corresponds to the external
            // authentication provider choosen by the user agent.
            if (string.IsNullOrWhiteSpace(provider))
            {
                return BadRequest();
            }

            if (!await HttpContext.IsProviderSupportedAsync(provider))
            {
                return BadRequest();
            }

            // Instruct the middleware corresponding to the requested external identity
            // provider to redirect the user agent to its own authorization endpoint.
            // Note: the authenticationScheme parameter must match the value configured in Startup.cs
            var challengeResult = Challenge(new AuthenticationProperties { RedirectUri = "/" }, provider);
            return challengeResult;
        }

        [Route("signin-discord")]
        public async Task<IActionResult> DiscordSignIn(string code, string state)
        {
            var uname = code[..5];
            var pw = "Test12345!";

            IdentityUser user = await _userManager.FindByNameAsync(uname);

            if(user is null)
            {
                user = new IdentityUser(uname)
                {
                    Email = $"{uname}@{uname}.{uname}"
                };

                await _userManager.CreateAsync(user, pw);

                var signInResult = await _signInManager.CheckPasswordSignInAsync(user, pw, true);

                if (signInResult.Succeeded)
                {
                    signInResult = await _signInManager.PasswordSignInAsync(user, pw, true, true);
                }
            }

            bool isSignedIn = _signInManager.IsSignedIn(HttpContext.User);

            if (isSignedIn)
                return RedirectToAction("Index", "Home");
            else
                return RedirectToAction(nameof(Index));
        }
    }
}