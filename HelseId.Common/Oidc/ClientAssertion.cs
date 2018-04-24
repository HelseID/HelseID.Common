using HelseId.Common.Certificates;
using HelseId.Common.Crypto;
using HelseId.Common.Jwt;
using IdentityModel;
using Microsoft.IdentityModel.Tokens;
using Newtonsoft.Json;

namespace HelseId.Common.Oidc
{
    public class ClientAssertion
    {
        [JsonProperty("client_assertion")] public string client_assertion { get; set; }

        [JsonProperty("client_assertion_type")]
        public string client_assertion_type { get; set; } = OidcConstants.ClientAssertionTypes.JwtBearer;

        public static ClientAssertion CreateWithRsaKeys(string clientId, string tokenEndpointUrl)
        {
            var rsa = RSAKeyGenerator.GetRsaParameters();
            var securityKey = new RsaSecurityKey(rsa);
            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl, JwtGenerator.SigningMethod.RsaSecurityKey,
                securityKey);

            return new ClientAssertion {client_assertion = assertion};
        }

        public static ClientAssertion CreateWithEnterpriseCertificate(string clientId, string tokenEndpointUrl,
            string thumbprint)
        {
            var certificate = CertificateStore.GetCertificateByThumbprint(thumbprint);
            var securityKey = new X509SecurityKey(certificate);
            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl,
                JwtGenerator.SigningMethod.X509EnterpriseSecurityKey, securityKey);

            return new ClientAssertion {client_assertion = assertion};
        }
    }
}