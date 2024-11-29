//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;
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
        /// <param name="accessToken">Slack access token</param>
        public SlackAuthenticatedContext(IOwinContext context, 
            string accessToken, string botUserId, JObject authenticatedUser, JObject incomingWebhook, JObject team, JObject user) 
            : base(context)
        {
            AccessToken = accessToken;
            BotUserId = botUserId;

            if (!string.IsNullOrEmpty(botUserId))
            {
                BotAccessToken = accessToken;
            }

            if (authenticatedUser != null) 
            {
                UserId = TryGetValue(authenticatedUser, "id");
            }

            if (incomingWebhook != null) 
            {
                // docs at https://api.slack.com/messaging/webhooks#incoming_webhooks_programmatic
                IncomingWebhookChannel = TryGetValue(incomingWebhook, "channel");
                IncomingWebhookChannel = TryGetValue(incomingWebhook, "channel_id");
                IncomingWebhookConfigUrl = TryGetValue(incomingWebhook, "configuration_url");
                IncomingWebhookUrl = TryGetValue(incomingWebhook, "url");
            }

            if (team != null) 
            {
                TeamId = TryGetValue(team, "id");
                TeamName = TryGetValue(team, "name");
            }

            if (user != null) 
            {
                UserId = TryGetValue(user, "id");
                UserName = TryGetValue(user, "name");
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
        /// Gets the fully qualified user ID
        /// </summary>
        public string UserSub 
        {
            get 
            {
                // per guidance from Slack team as discussed in dev4slack team 
                // the user's identity should be fully qualified with the team identity
                return String.Format("{0}_{1}", TeamId, UserId);
            }
        }

        /// <summary>
        /// If requesting access for a bot gets the user ID for the bot user
        /// </summary>
        public string BotUserId { get; private set; }

        /// <summary>
        /// Gets the fully qualified bot user ID
        /// </summary>
        public string BotUserSub {
            get 
            {
                // per guidance from Slack team as discussed in dev4slack team 
                // the user's identity should be fully qualified with the team identity
                return !String.IsNullOrEmpty(BotUserId) ? String.Format("{0}_{1}", TeamId, BotUserId) : null;
            }
        }

        /// <summary>
        /// If requesting access for a bot gets the access token to be used by the bot
        /// </summary>
        public string BotAccessToken { get; private set; }

        public string IncomingWebhookChannel { get; private set; }

        public string IncomingWebhookChannelId { get; private set; }

        public string IncomingWebhookConfigUrl { get; private set; }

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
