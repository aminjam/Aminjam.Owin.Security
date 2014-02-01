// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Aminjam.Owin.Security.Fitbit
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class FitbitAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="FitbitAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Fitbit Access token</param>
        /// <param name="expires">Seconds until expiration</param>
        public FitbitAuthenticatedContext(IOwinContext context, JObject user, string accessToken, string accessTokenSecret, string userId)
            : base(context)
        {
            User = user;
            AccessToken = accessToken;
            AccessTokenSecret = accessTokenSecret;
            Id = userId;
            FullName = TryGetValue(user, "fullName");
        }

        /// <summary>
        /// Gets the JSON-serialized user
        /// </summary>
        public JObject User { get; private set; }

        /// <summary>
        /// Gets the Fitbit access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the Fitbit access token
        /// </summary>
        public string AccessTokenSecret { get; private set; }

        /// <summary>
        /// Gets the Fitbit user ID
        /// </summary>
        public string Id { get; private set; }

        /// <summary>
        /// Gets the user's name
        /// </summary>
        public string FullName { get; private set; }

        /// <summary>
        /// Gets the user's email
        /// </summary>
        public string Email { get; private set; }


        /// <summary>
        /// Gets the <see cref="ClaimsIdentity"/> representing the user
        /// </summary>
        public ClaimsIdentity Identity { get; set; }

        /// <summary>
        /// Gets or sets a property bag for common authentication properties
        /// </summary>
        public AuthenticationProperties Properties { get; set; }

        private static string TryGetValue(JObject user, string propertyName)
        {
            JToken value;
            return user.TryGetValue(propertyName, out value) ? value.ToString() : null;
        }
    }
}
