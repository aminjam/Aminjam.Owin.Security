// Copyright (c) Microsoft Open Technologies, Inc. All rights reserved. See License.txt in the project root for license information.

using System;
using Microsoft.Owin.Security;
using Aminjam.Owin.Security.Glass;

namespace Owin
{
    /// <summary>
    /// Extension methods for using <see cref="GlassAuthenticationMiddleware"/>
    /// </summary>
    public static class GlassAuthenticationExtensions
    {
        /// <summary>
        /// Authenticate users using Facebook
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="options">Middleware configuration options</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseGlassAuthentication(this IAppBuilder app, GlassAuthenticationOptions options)
        {
            if (app == null)
            {
                throw new ArgumentNullException("app");
            }
            if (options == null)
            {
                throw new ArgumentNullException("options");
            }

            app.Use(typeof(GlassAuthenticationMiddleware), app, options);
            return app;
        }

        /// <summary>
        /// Authenticate users using Facebook
        /// </summary>
        /// <param name="app">The <see cref="IAppBuilder"/> passed to the configuration method</param>
        /// <param name="clientId">The appId assigned by Facebook</param>
        /// <param name="clientSecret">The appSecret assigned by Facebook</param>
        /// <returns>The updated <see cref="IAppBuilder"/></returns>
        public static IAppBuilder UseGlassAuthentication(
            this IAppBuilder app,
            string clientId,
            string clientSecret)
        {
            return UseGlassAuthentication(
                app,
                new GlassAuthenticationOptions
                {
                    ClientId = clientId,
                    ClientSecret = clientSecret,
                });
        }
    }
}
