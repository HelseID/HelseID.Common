using System;	
using System.Collections.Generic;	
using System.IdentityModel.Tokens.Jwt;	
using System.Security.Claims;	
using System.Security.Cryptography;	
using System.Security.Cryptography.X509Certificates;	
using HelseId.Common.Extensions;	
using IdentityModel;	
using Microsoft.IdentityModel.Tokens;	
	
namespace HelseId.Common.ClientAssertion
{	
    public partial class JwtGenerator
    {	
        private const double DefaultExpiryInHours = 10;	
	
        /// <summary>	
        ///     This methods generates a client assertion jwt as specified in https://tools.ietf.org/html/rfc7523	
        /// </summary>	
        /// <param name="clientId">The client Id used as sub</param>	
        /// <param name="tokenEndpoint">The token endpoint used as aud</param>	
        /// <param name="signingMethod">Indicate which method to use when signing the Jwt Token</param>	
        /// <param name="securityKey">The security key to sign the assertion with</param>	
        /// <returns>A client assertion jwt in compact serialization format.</returns>	
        public static string Generate(string clientId, string tokenEndpoint, SigningMethod signingMethod,
            SecurityKey securityKey)
        {	
            if (clientId.IsNullOrEmpty())	
                throw new ArgumentException("clientId can not be empty or null");	
	
            if (tokenEndpoint.IsNullOrEmpty())	
                throw new ArgumentException("The token endpoint address can not be empty or null");	
	
            if (securityKey == null)	
                throw new ArgumentException("The security key can not be null");	
            return GenerateJwt(clientId, tokenEndpoint, null, signingMethod, securityKey);	
        }	
	
        private static string GenerateJwt(string clientId, string audience, DateTime? expiryDate,
            SigningMethod signingMethod, SecurityKey securityKey)
        {	
            var signingCredentials = new SigningCredentials(securityKey, SecurityAlgorithms.RsaSha512);	
	
            var jwt = CreateJwtSecurityToken(clientId, audience, expiryDate, signingCredentials);	
	
            if (signingMethod == SigningMethod.X509EnterpriseSecurityKey)	
                UpdateJwtHeader(securityKey, jwt);	
	
            var tokenHandler = new JwtSecurityTokenHandler();	
            return tokenHandler.WriteToken(jwt);	
        }	
	
        private static void UpdateJwtHeader(SecurityKey key, JwtSecurityToken token)
        {	
            if (key is X509SecurityKey x509Key)	
            {	
                var thumbprint = Base64Url.Encode(x509Key.Certificate.GetCertHash());	
                var x5c = GenerateX5c(x509Key.Certificate);	
                var pubKey = x509Key.PublicKey as RSA;	
                var parameters = pubKey.ExportParameters(false);	
                var exponent = Base64Url.Encode(parameters.Exponent);	
                var modulus = Base64Url.Encode(parameters.Modulus);	
	
                token.Header.Add("x5c", x5c);	
                token.Header.Add("kty", pubKey.SignatureAlgorithm);	
                token.Header.Add("use", "sig");	
                token.Header.Add("x5t", thumbprint);	
                token.Header.Add("e", exponent);	
                token.Header.Add("n", modulus);	
            }	
	
            if (key is RsaSecurityKey rsaKey)	
            {	
                var parameters = rsaKey.Rsa?.ExportParameters(false) ?? rsaKey.Parameters;	
                var exponent = Base64Url.Encode(parameters.Exponent);	
                var modulus = Base64Url.Encode(parameters.Modulus);	
	
                token.Header.Add("kty", "RSA");	
                token.Header.Add("use", "sig");	
                token.Header.Add("e", exponent);	
                token.Header.Add("n", modulus);	
            }	
        }	
	
        private static List<string> GenerateX5c(X509Certificate2 certificate)
        {	
            var x5c = new List<string>();	
            var chain = GetCertificateChain(certificate);	
            if (chain != null)	
                foreach (var cert in chain.ChainElements)	
                {	
                    var x509Base64 = Convert.ToBase64String(cert.Certificate.RawData);	
                    x5c.Add(x509Base64);	
                }	
	
            return x5c;	
        }	
	
        private static X509Chain GetCertificateChain(X509Certificate2 cert)
        {	
            var certificateChain = X509Chain.Create();	
            certificateChain.ChainPolicy.RevocationMode = X509RevocationMode.NoCheck;	
            certificateChain.Build(cert);	
            return certificateChain;	
        }	
	
        private static JwtSecurityToken CreateJwtSecurityToken(string clientId, string audience, DateTime? expiryDate,
            SigningCredentials signingCredentials)
        {	
            var exp = new DateTimeOffset(expiryDate ?? DateTime.Now.AddHours(DefaultExpiryInHours));	
	
            var claims = new List<Claim>
            {	
                new Claim(JwtClaimTypes.Subject, clientId),	
                new Claim(JwtClaimTypes.IssuedAt, exp.ToUnixTimeSeconds().ToString()),	
                new Claim(JwtClaimTypes.JwtId, Guid.NewGuid().ToString("N"))	
            };	
	
            var token = new JwtSecurityToken(clientId, audience, claims, DateTime.Now, DateTime.Now.AddHours(10),
signingCredentials);	
	
            return token;	
        }	
    }	
} 