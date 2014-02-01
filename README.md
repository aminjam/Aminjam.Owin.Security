Aminjam.Owin.Security
=====================

Extending the default Microsoft.Owin.Security implementation for the OAuth providers to Instagram, Foursquare, Google Glass, and Fitbit

## Purpose ##

ASP.NET MVC5 ships with a few default OAuth Providers e.g. Facebook and Google. This project will help add a few other useful OAuth providers to that list. If Microsoft decides to add their own implementation, I will be removing these to keep the consistency. It is important to note that like all OAuth provider, the identity of the signed up user with the OAuth provider may or may not have been verified.


## Instructions ##

Setting up Apps for redirect URI:

- **Instagram**: **HOST**/signin-instagram
- **Foursquare**: **HOST**/signin-foursquare
- **Fitbit**: **HOST**/signin-fitbit
- **Glass**: **HOST**/signin-glass
 
1. Create a new ASP.NET MVC 5 project, choosing the Individual User Accounts authentication type.
2. In ~/App_Start/Startup.Auth.cs under ConfigureAuth function

```C#
app.UseInstagramAuthentication(new InstagramAuthenticationOptions
{
	ClientId = "Instagram App ClientId",
	ClientSecret = "Instagram App Secret"
});
app.UseFoursquareAuthentication(new FoursquareAuthenticationOptions
{
	ClientId = "Foursquare App ClientId",
	ClientSecret = "Foursquare App Secret"
});
app.UseFitbitAuthentication(new FitbitAuthenticationOptions
{
	ClientId = "Fitbit App ClientId",
	ClientSecret = "Fitbit App Secret"
});
app.UseGlassAuthentication(new GlassAuthenticationOptions
{
	ClientId = "Google Developer Console App ClientId",
	ClientSecret = "Google Developer Console App Secret",
	Scope = new List<string>
	{
		"https://www.googleapis.com/auth/glass.timeline",
		"https://www.googleapis.com/auth/userinfo.profile",
		"https://www.googleapis.com/auth/userinfo.email"
	}
});
```
You can always find the created access token or other information by creating a provider

```C#
app.UseFitbitAuthentication(new FitbitAuthenticationOptions
{
	ClientId = "Fitbit App ClientId",
	ClientSecret = "Fitbit App Secret",
	Provider = new FitbitAuthenticationProvider()
	{
		OnAuthenticated = (context) =>
		{
			context.Identity.AddClaim(new Claim("urn::fitbit::accesstoken", context.AccessToken));
			return Task.FromResult(0);
		}
	}
});
```
## Thanks To ##

Special thanks to [Katana Project](http://katanaproject.codeplex.com)
