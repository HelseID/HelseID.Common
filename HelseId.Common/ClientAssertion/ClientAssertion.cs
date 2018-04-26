using HelseId.Common.Crypto;	
using IdentityModel;	
using Microsoft.IdentityModel.Tokens;	
	
	
namespace HelseId.Common.ClientAssertion
{	
    public class ClientAssertion
    {	
        public string Assertion { get; set; }	
	
        public string AssertionType { get; set; } = OidcConstants.ClientAssertionTypes.JwtBearer;	
	
        public static ClientAssertion CreateWithRsaKeys(string clientId, string tokenEndpointUrl)
        {	
            var rsa = RSAKeyGenerator.GetRsaParameters(clientId);	
            var securityKey = new RsaSecurityKey(rsa);	
            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl, JwtGenerator.SigningMethod.RsaSecurityKey,
securityKey);	
	
            return new ClientAssertion
            {
                Assertion = assertion
            };	
        }	
	
        public static ClientAssertion CreateWithEnterpriseCertificate(string clientId, string tokenEndpointUrl,
            string thumbprint)
        {	
            var certificate = CertificateStore.GetCertificateByThumbprint(thumbprint);	
            var securityKey = new X509SecurityKey(certificate);	
            var assertion = JwtGenerator.Generate(clientId, tokenEndpointUrl,
JwtGenerator.SigningMethod.X509EnterpriseSecurityKey, securityKey);	
	
            return new ClientAssertion { Assertion = assertion };	
        }	
    }	
} 