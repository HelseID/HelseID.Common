using System;
using System.Threading.Tasks;
using HelseId.Common.Browser;
using HelseId.Common.Network;
using IdentityModel.Client;
using IdentityModel.OidcClient;
using static HelseId.Common.ClientAssertion.JwtGenerator;

namespace HelseId.Common.Clients
{
    public interface IHelseIdClient
    {
        Task<LoginResult> Login();
        Task<TokenResponse> ClientCredentialsSignIn();
        Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code);
        Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken);
        Task<TokenResponse> TokenExchange(string accessToken);
    }

    /// <summary>
    ///     The HelseIdClient is a specialized client used to handle the extensions made on IdentityServer by HelseId.
    ///     It consists of an implementation of the client assertions by use of RSA-keys or Enterprise Certificates.
    ///     In addition to an implementaition of the token exchange grant type which HelseId supports.
    ///     If one only need standard OAuth and OIDC functionality it is recomended to use the standard clients such as
    ///     IdentityModel.OidcClient
    ///     and IdentityModel.Client.TokenClient as they provide this functinality and the HelseIdClient uses these internaly
    ///     anyway.
    /// </summary>
    public class HelseIdClient : IHelseIdClient
    {
        private readonly OidcClient _oidcClient;
        private readonly HelseIdClientOptions _options;

        public HelseIdClient(HelseIdClientOptions options)
        {
            options.Check();

            _options = options;
            if (_options.Browser == null) _options.Browser = new SystemBrowser(_options.RedirectUri);
            _oidcClient = new OidcClient(_options);
        }

        /// <summary>
        ///     Starts a login.
        /// </summary>
        /// <returns>A login result containing the tokens and codes relevant for the given flow selected.</returns>
        public async Task<LoginResult> Login()
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var result = await _oidcClient.LoginAsync(new LoginRequest
            {
                BackChannelExtraParameters = GetBackChannelExtraParameters(disco),
                FrontChannelExtraParameters = GetFrontChannelExtraParameters()
            });

            return result;
        }

        /// <summary>
        ///     Request a token based on client credentials.
        /// </summary>
        /// <returns>Returns a token response from a OpenId Connect/OAuth token endpoint</returns>
        public async Task<TokenResponse> ClientCredentialsSignIn()
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestClientCredentialsAsync(_options.Scope, extraParams);

            return result;
        }


        /// <summary>
        ///     Request a token using a authorization code
        /// </summary>
        /// <param name="code">A valid authorization code</param>
        /// <returns>Returns a token response from a OpenId Connect/OAuth token endpoint</returns>
        public async Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestAuthorizationCodeAsync(code, _options.RedirectUri, string.Empty, extraParams);

            return result;
        }


        /// <summary>
        ///     Request a token using a refresh token
        /// </summary>
        /// <param name="refreshToken">A valid refresh token</param>
        /// <returns>Returns a token response from a OpenId Connect/OAuth token endpoint</returns>
        public async Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken)
        {
            var disco = await OidcDiscoveryHelper.GetDiscoveryDocument(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);

            var extraParams = GetBackChannelExtraParameters(disco);
            var c = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);
            var result = await c.RequestRefreshTokenAsync(refreshToken, extraParams);

            return result;
        }

        /// <summary>
        ///     Implementation loosely based on https://tools.ietf.org/html/draft-ietf-oauth-token-exchange-10
        ///     Exchanges a valid access token from a trusted issuer with a new access token.
        ///     HelseID specific claims and sub are copied over as claims on the new token. The exchange chain is also represented
        ///     in the act claim structure.
        ///     The requested scopes will also be added to the access token.
        /// </summary>
        /// <param name="accessToken">A valid access token </param>
        /// <returns>An access token</returns>
        public async Task<TokenResponse> TokenExchange(string accessToken)
        {
            if (string.IsNullOrEmpty(accessToken)) throw new ArgumentNullException(nameof(accessToken));

            var disco = await DiscoveryClient.GetAsync(_options.Authority);
            if (disco.IsError) throw new Exception(disco.Error);
            var client = new TokenClient(disco.TokenEndpoint, _options.ClientId, _options.ClientSecret);

            var payload = GetBackChannelExtraParameters(disco, accessToken);

            var response = await client.RequestCustomGrantAsync("token_exchange", _options.Scope, payload);

            return response;
        }

        private object GetBackChannelExtraParameters(DiscoveryResponse disco, string token = null)
        {
            ClientAssertion.ClientAssertion assertion = null;
            if (_options.SigningMethod == SigningMethod.RsaSecurityKey)
                assertion = ClientAssertion.ClientAssertion.CreateWithRsaKeys(_options.ClientId, disco.TokenEndpoint);
            else if (_options.SigningMethod == SigningMethod.X509EnterpriseSecurityKey)
                assertion = ClientAssertion.ClientAssertion.CreateWithEnterpriseCertificate(_options.ClientId, disco.TokenEndpoint,
                    _options.CertificateThumbprint);

            var payload = new
            {
                token,
                client_assertion = assertion?.Assertion,
                client_assertion_type = assertion?.AssertionType
            };

            return payload;
        }

        private object GetFrontChannelExtraParameters()
        {
            var preselectIdp = _options.PreselectIdp;

            if (string.IsNullOrEmpty(preselectIdp))
                return null;

            return new {acr_values = preselectIdp, prompt = "Login"};
        }
    }
}