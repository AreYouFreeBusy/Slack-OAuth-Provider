//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Globalization;
using System.Security.Claims;
using Microsoft.Owin;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Provider;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Slack
{
    /// <summary>
    /// Contains information about the login session as well as the user <see cref="System.Security.Claims.ClaimsIdentity"/>.
    /// </summary>
    public class SlackAuthenticatedContext : BaseContext
    {
        /// <summary>
        /// Initializes a <see cref="SlackAuthenticatedContext"/>
        /// </summary>
        /// <param name="context">The OWIN environment</param>
        /// <param name="user">The JSON-serialized user</param>
        /// <param name="accessToken">Azure AD Access token</param>
        public SlackAuthenticatedContext(
            IOwinContext context, string accessToken, JObject user, JObject bot, JObject incomingWebhook) 
            : base(context)
        {
            AccessToken = accessToken;

            if (user != null) 
            {
                TeamId = TryGetValue(user, "team_id");
                TeamName = TryGetValue(user, "team");
                UserId = TryGetValue(user, "user_id");
                UserName = TryGetValue(user, "user");
            }

            if (bot != null) 
            {
                BotAccessToken = TryGetValue(bot, "bot_access_token");
                BotUserId = TryGetValue(bot, "bot_user_id");
            }

            if (incomingWebhook != null) 
            {
                IncomingWebhookChannel = TryGetValue(incomingWebhook, "channel");
                IncomingWebhookConfigUrl = TryGetValue(incomingWebhook, "configuration_url");
                IncomingWebhookUrl = TryGetValue(incomingWebhook, "url");
            }
        }

        /// <summary>
        /// Gets the Slack OAuth access token
        /// </summary>
        public string AccessToken { get; private set; }

        /// <summary>
        /// Gets the team ID
        /// </summary>
        public string TeamId { get; private set; }

        /// <summary>
        /// Gets the team name
        /// </summary>
        public string TeamName { get; private set; }

        /// <summary>
        /// Gets the user ID
        /// </summary>
        public string UserId { get; private set; }

        /// <summary>
        /// Gets the username
        /// </summary>
        public string UserName { get; private set; }

        /// <summary>
        /// If requesting access for a bot gets the user ID for the bot user
        /// </summary>
        public string BotUserId { get; private set; }

        /// <summary>
        /// If requesting access for a bot gets the access token to be used by the bot
        /// </summary>
        public string BotAccessToken { get; private set; }

        /// <summary>
        /// Gets the username
        /// </summary>
        public string IncomingWebhookChannel { get; private set; }

        /// <summary>
        /// If requesting access for a bot gets the user ID for the bot user
        /// </summary>
        public string IncomingWebhookConfigUrl { get; private set; }

        /// <summary>
        /// If requesting access for a bot gets the access token to be used by the bot
        /// </summary>
        public string IncomingWebhookUrl { get; private set; }

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
