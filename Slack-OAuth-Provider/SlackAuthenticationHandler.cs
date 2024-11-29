//  Copyright 2015 Stefan Negritoiu. See LICENSE file for more information.

using System;
using System.Collections.Generic;
using System.Net.Http;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.Owin;
using Microsoft.Owin.Infrastructure;
using Microsoft.Owin.Logging;
using Microsoft.Owin.Security;
using Microsoft.Owin.Security.Infrastructure;
using Newtonsoft.Json;
using Newtonsoft.Json.Linq;

namespace Owin.Security.Providers.Slack
{
    public class SlackAuthenticationHandler : AuthenticationHandler<SlackAuthenticationOptions>
    {
        // see https://api.slack.com/docs/oauth for docs 
        private const string AuthorizeEndpoint = "https://slack.com/oauth/v2/authorize";
        private const string TokenEndpoint = "https://slack.com/api/oauth.v2.access";
        private const string UserInfoEndpoint = "https://slack.com/api/users.info";
        private const string XmlSchemaString = "http://www.w3.org/2001/XMLSchema#string";

        private readonly HttpClient _httpClient;
        private readonly ILogger _logger;

        public SlackAuthenticationHandler(HttpClient httpClient, ILogger logger)
        {
            _httpClient = httpClient;
            _logger = logger;
        }


        protected override async Task<AuthenticationTicket> AuthenticateCoreAsync()
        {
            AuthenticationProperties properties = null;

            try
            {
                string state = null;
                string code = null;

                IReadableStringCollection query = Request.Query;
                IList<string> values;
                
                values = query.GetValues("state");
                if (values != null && values.Count == 1) 
                {
                    state = values[0];
                }
                properties = Options.StateDataFormat.Unprotect(state);
                if (properties == null) 
                {
                    return null;
                }

                values = query.GetValues("error");
                if (values != null && values.Count == 1) 
                {
                    return new AuthenticationTicket(null, properties);
                }
                
                values = query.GetValues("code");
                if (values != null && values.Count == 1) 
                {
                    code = values[0];
                }

                // OAuth2 10.12 CSRF
                if (!ValidateCorrelationId(properties, _logger))
                {
                    return new AuthenticationTicket(null, properties);
                }

                string requestPrefix = Request.Scheme + "://" + Request.Host;
                string redirectUri = requestPrefix + Request.PathBase + Options.CallbackPath;

                // Build up the body for the token request
                var body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("grant_type", "authorization_code"));
                body.Add(new KeyValuePair<string, string>("code", code));
                body.Add(new KeyValuePair<string, string>("redirect_uri", redirectUri));
                body.Add(new KeyValuePair<string, string>("client_id", Options.ClientId));
                body.Add(new KeyValuePair<string, string>("client_secret", Options.ClientSecret));

                // Request the token
                var tokenResponse = await _httpClient.PostAsync(TokenEndpoint, new FormUrlEncodedContent(body));
                tokenResponse.EnsureSuccessStatusCode();
                var content = await tokenResponse.Content.ReadAsStringAsync();

                // Deserializes the token response
                var tokenJson = JsonConvert.DeserializeObject<JObject>(content);
                var accessToken = tokenJson.Value<string>("access_token");
                var authenticatedUser = tokenJson.Value<JObject>("authed_user");
                var botUserId = tokenJson.Value<string>("bot_user_id");
                var incomingWebhook = tokenJson.Value<JObject>("incoming_webhook");
                var team = tokenJson.Value<JObject>("team");

                // Build up the body for the user request
                body = new List<KeyValuePair<string, string>>();
                body.Add(new KeyValuePair<string, string>("token", accessToken));
                body.Add(new KeyValuePair<string, string>("user", authenticatedUser?.Value<string>("id")));

                // Get the Slack user
                JObject user = null;
                var userResponse = await _httpClient.PostAsync(UserInfoEndpoint, new FormUrlEncodedContent(body));
                if (userResponse.IsSuccessStatusCode) {
                    var userContent = await userResponse.Content.ReadAsStringAsync();
                    var userJson = JsonConvert.DeserializeObject<JObject>(userContent);
                    user = tokenJson.Value<JObject>("user");
                }

                var context = new SlackAuthenticatedContext(Context, accessToken, botUserId, authenticatedUser, incomingWebhook, team, user);
                context.Identity = new ClaimsIdentity(
                    Options.AuthenticationType,
                    ClaimsIdentity.DefaultNameClaimType,
                    ClaimsIdentity.DefaultRoleClaimType);

                if (!string.IsNullOrEmpty(context.BotUserId ?? context.UserId)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimTypes.NameIdentifier, context.BotUserId ?? context.UserId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.BotUserId ?? context.UserName)) 
                {
                    context.Identity.AddClaim(
                        new Claim(ClaimsIdentity.DefaultNameClaimType, context.BotUserId ?? context.UserName, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.TeamId)) 
                {
                    context.Identity.AddClaim(new Claim("urn:slack:teamid", context.TeamId, XmlSchemaString, Options.AuthenticationType));
                }
                if (!string.IsNullOrEmpty(context.TeamName)) 
                {
                    context.Identity.AddClaim(new Claim("urn:slack:teamname", context.TeamName, XmlSchemaString, Options.AuthenticationType));
                }
                context.Properties = properties;

                await Options.Provider.Authenticated(context);

                return new AuthenticationTicket(context.Identity, context.Properties);
            }
            catch (Exception ex)
            {
                _logger.WriteError("Authentication failed", ex);
                return new AuthenticationTicket(null, properties);
            }
        }


        protected override Task ApplyResponseChallengeAsync()
        {
            if (Response.StatusCode != 401)
            {
                return Task.FromResult<object>(null);
            }

            AuthenticationResponseChallenge challenge = 
                Helper.LookupChallenge(Options.AuthenticationType, Options.AuthenticationMode);

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

                var queryStrings = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                queryStrings.Add("response_type", "code");
                queryStrings.Add("client_id", Options.ClientId);
                queryStrings.Add("redirect_uri", redirectUri);

                // default scope
                if (Options.Scope.IndexOf("identify") < 0) 
                {
                    Options.Scope.Add("identify");
                }
                AddQueryString(queryStrings, properties, "scope", string.Join(" ", Options.Scope));

                // team parameter is specific to Slack, similar to login_hint
                if (!String.IsNullOrEmpty(Options.Team)) 
                {
                    AddQueryString(queryStrings, properties, "team", Options.Team);
                }

                string state = Options.StateDataFormat.Protect(properties);
                queryStrings.Add("state", state);

                string authorizationEndpoint = WebUtilities.AddQueryString(AuthorizeEndpoint, queryStrings);

                Response.Redirect(authorizationEndpoint);
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
                AuthenticationTicket ticket = await AuthenticateAsync();
                if (ticket == null)
                {
                    _logger.WriteWarning("Invalid return state, unable to redirect.");
                    Response.StatusCode = 500;
                    return true;
                }

                var context = new SlackReturnEndpointContext(Context, ticket);
                context.SignInAsAuthenticationType = Options.SignInAsAuthenticationType;
                context.RedirectUri = ticket.Properties.RedirectUri;

                await Options.Provider.ReturnEndpoint(context);

                if (context.SignInAsAuthenticationType != null && context.Identity != null)
                {
                    ClaimsIdentity grantIdentity = context.Identity;
                    if (!string.Equals(
                        grantIdentity.AuthenticationType, context.SignInAsAuthenticationType, StringComparison.Ordinal))
                    {
                        grantIdentity = new ClaimsIdentity(
                            grantIdentity.Claims, 
                            context.SignInAsAuthenticationType, 
                            grantIdentity.NameClaimType, 
                            grantIdentity.RoleClaimType);
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


        private static void AddQueryString(IDictionary<string, string> queryStrings, AuthenticationProperties properties,
            string name, string defaultValue = null) 
        {
            string value;
            if (!properties.Dictionary.TryGetValue(name, out value)) 
            {
                value = defaultValue;
            }
            else 
            {
                // Remove the parameter from AuthenticationProperties so it won't be serialized to state parameter
                properties.Dictionary.Remove(name);
            }

            if (value == null) 
            {
                return;
            }

            queryStrings[name] = value;
        }
    }
}