Aminjam.Owin.Security
=====================

Extending the default Microsoft.Owin.Security implementation for the OAuth providers to Instagram, Foursquare, Google Glass, and Fitbit

## Purpose ##

ASP.NET MVC5 ships with a few default OAuth Providers e.g. Facebook and Google. It is important to note that like all OAuth provider, the identity of the signed up user with the OAuth provider may or may not have been verified.


## Instructions ##

Setting up Apps for redirect URI:
Instagram: <Your HOST>/signin-instagram
Foursquare: <Your HOST>/signin-foursquare
 
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
}
```

## Thanks To ##

Special thanks to [Katana Project](http://katanaproject.codeplex.com)