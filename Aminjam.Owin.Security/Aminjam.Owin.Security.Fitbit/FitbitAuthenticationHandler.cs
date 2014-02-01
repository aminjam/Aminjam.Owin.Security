// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System.IO;
using System.Linq;
using System.Net;
using System.Net.Http.Headers;
using System.Security.Cryptography;
using System.Text;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json.Linq;
using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using OAuth;

namespace Aminjam.Owin.Security.Fitbit
{
    internal class FitbitAuthenticationHandler : AuthenticationHandler<FitbitAuthenticationOptions>
    {
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";
        private const string RequestTokenEndpoint = "https://api.fitbit.com/oauth/request_token";
        private const string AccessTokenEndpoint = "https://api.fitbit.com/oauth/access_token";
        private const string AuthenticateEndpoint = "https://www.fitbit.com/oauth/authenticate";
        private const string SelfEndpointTemplate = "https://api.fitbit.com/1/user/-/profile.json";
        private const string AcceptedOAuth = "http://www.fitbit.com/oauth/oauth_allow";

        private static string OAuthTokenSecret = "";
        private static string OAuthState = "";

        private readonly ILogger _logger;
        private readonly HttpClient _httpClient;

        public FitbitAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }

        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string oauth_token = null;
                string oauth_verifier = null;
                string state = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values = query.GetValues("oauth_token");
                if (values != null && values.Count == 1)
                {
                    oauth_token = values[0];
                }
                values = query.GetValues("oauth_verifier");
                if (values != null && values.Count == 1)
                {
                    oauth_verifier = values[0];
                }

                properties = Options.StateDataFormat.Unprotect(OAuthState);
                if (properties == null)
                {
                    return null;
                }

                var requestPrefix = Request.Scheme + "://" + Request.Host;
                var redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                var client = new OAuthRequest
                {
                    ConsumerKey = Options.ClientId,
                    ConsumerSecret = Options.ClientSecret,
                    Type = OAuthRequestType.AccessToken,
                    SignatureMethod = OAuthSignatureMethod.HmacSha1,
                    RequestUrl = AccessTokenEndpoint,
                    Version = "1.0",
                    Method = "POST",
                    Token = oauth_token,
                    TokenSecret = OAuthTokenSecret,
                    Verifier = oauth_verifier
                };
                var auth = client.GetAuthorizationHeader().Replace("OAuth ", "");
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", auth);
                var response = _httpClient.PostAsync(client.RequestUrl, null).Result;
                response.EnsureSuccessStatusCode();

                var textArray = response.Content.ReadAsStringAsync().Result.Split('&');
                var accessToken = textArray.First(i => i.Contains("oauth_token=")).Replace("oauth_token=", "");
                var accessTokenSecret = textArray.First(i => i.Contains("oauth_token_secret=")).Replace("oauth_token_secret=", "");
                var encodedUserId = textArray.First(i => i.Contains("encoded_user_id=")).Replace("encoded_user_id=", "");

                client = new OAuthRequest
                {
                    ConsumerKey = Options.ClientId,
                    ConsumerSecret = Options.ClientSecret,
                    Type = OAuthRequestType.ProtectedResource,
                    SignatureMethod = OAuthSignatureMethod.HmacSha1,
                    RequestUrl = SelfEndpointTemplate,
                    Version = "1.0",
                    Method = "GET",
                    Token = accessToken,
                    TokenSecret = accessTokenSecret
                };
                auth = client.GetAuthorizationHeader().Replace("OAuth ", "");
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", auth);
                response = _httpClient.GetAsync(client.RequestUrl).Result;
                response.EnsureSuccessStatusCode();

                var text = await response.Content.ReadAsStringAsync();
                dynamic self = JObject.Parse(text);
                JObject user = self.user;

                var context = new FitbitAuthenticatedContext(Context, user, accessToken, accessTokenSecret, encodedUserId)
                {
                    Identity = new ClaimsIdentity(
                        Options.AuthenticationType,
                        ClaimsIdentity.DefaultNameClaimType,
                        ClaimsIdentity.DefaultRoleClaimType)
                };

                if (!string.IsNullOrEmpty(context.Id))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, context.Id, XmlSchemaString,
                        Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FullName))
                {
                    context.Identity.AddClaim(new Claim(ClaimsIdentity.DefaultNameClaimType, context.FullName,
                        XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.FullName))
                {
                    context.Identity.AddClaim(new Claim("urn:fitbit:fullName", context.FullName, XmlSchemaString,
                        Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.Email))
                {
                    context.Identity.AddClaim(new Claim(ClaimTypes.Email, context.Email, XmlSchemaString,
                        Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);

            }
            catch (Exception ex)
            {
                _logger.WriteError(ex.Message);
            }
            return new AuthenticationTicket(null, properties);
        }

        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

            if (challenge != null)
            {
                string baseUri =
                    Request.Scheme +
                    Uri.SchemeDelimiter +
                    Request.Host +
                    Request.PathBase;

                string currentUri =
                    baseUri +
                    Request.Path +
                    Request.QueryString;

                string redirectUri =
                    baseUri +
                    Options.CallbackPath;

                AuthenticationProperties properties = challenge.Properties;
                if (string.IsNullOrEmpty(properties.RedirectUri))
                {
                    properties.RedirectUri = currentUri;
                }

                // OAuth2 10.12 CSRF
                GenerateCorrelationId(properties);

                // comma separated
                string scope = string.Join(",", Options.Scope);

                string state = Options.StateDataFormat.Protect(properties);

                var client = new OAuthRequest
                {
                    ConsumerKey = Options.ClientId,
                    ConsumerSecret = Options.ClientSecret,
                    Type = OAuthRequestType.RequestToken,
                    SignatureMethod = OAuthSignatureMethod.HmacSha1,
                    RequestUrl = RequestTokenEndpoint,
                    Version = "1.0",
                    Method = "POST"
                };
                var auth = client.GetAuthorizationHeader().Replace("OAuth ", "");
                _httpClient.DefaultRequestHeaders.Authorization = new AuthenticationHeaderValue("OAuth", auth);
                var response = _httpClient.PostAsync(client.RequestUrl, null).Result;
                response.EnsureSuccessStatusCode();
                var textArray = response.Content.ReadAsStringAsync().Result.Split('&');
                var parameters = "?" + textArray.First(i => i.Contains("oauth_token="));

                OAuthState = state;
                OAuthTokenSecret = textArray.First(i => i.Contains("oauth_token_secret=")).Replace("oauth_token_secret=", "");
                
                Response.Redirect(AuthenticateEndpoint + parameters);
            }

            return Task.FromResult<object>(null);
        }

        public override async Task<bool> InvokeAsync()
        {
            return await InvokeReplyPathAsync();
        }

        private async Task<bool> InvokeReplyPathAsync()
        {
            if (Options.CallbackPath.HasValue && Options.CallbackPath == Request.Path)
            {
                // TODO: error responses

                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new FitbitReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null &&
                    context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(grantIdentity.Claims, context.SignInAsAuthenticationType, grantIdentity.NameClaimType, grantIdentity.RoleClaimType);
                    }
                    Context.Authentication.SignIn(context.Properties, grantIdentity);
                }

                if (!context.IsRequestCompleted && context.RedirectUri != null)
                {
                    string redirectUri = context.RedirectUri;
                    if (context.Identity == null)
                    {
                        // add a redirect hint that sign-in failed in some way
                        redirectUri = WebUtilities.AddQueryString(redirectUri, "error", "access_denied");
                    }
                    Response.Redirect(redirectUri);
                    context.RequestCompleted();
                }

                return context.IsRequestCompleted;
            }
            return false;
        }
    }
}
