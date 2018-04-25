using System;
using HelseId.Common.Crypto;
using IdentityModel.OidcClient;
using static HelseId.Common.Jwt.JwtGenerator;

namespace HelseId.Common.Clients
{
    public class HelseIdClientOptions : OidcClientOptions
    {
        /// <summary>
        ///     The thumbprint of the certificate to use for client assertion.
        /// </summary>
        /// <value>
        ///     The certificate thumbprint.
        /// </value>
        public string CertificateThumbprint { get; set; }

        /// <summary>
        ///     The SigningMethod to use for client assertion
        /// </summary>
        /// <value>
        ///     The signing method. None, X509SecurityKey, RsaSecurityKey or X509EnterpriseSecurityKey.
        /// </value>
        public SigningMethod SigningMethod { get; set; }

        /// <summary>
        ///     Specify which identity provider to use
        /// </summary>
        /// <value>
        ///     The identity provider.
        /// </value>
        public string PreselectIdp { get; set; }


        /// <summary>
        ///     Runs a quick check to see it the options are correctly setup. Note that this is only a shallow check and the
        ///     options can still be invalid.
        /// </summary>
        /// <param name="throwException">Specifies if the check should throw an exception if the check fails or just return false.</param>
        /// <returns></returns>
        public bool Check(bool throwException = true)
        {
            try
            {
                if (string.IsNullOrEmpty(Authority)) throw new NullReferenceException("Authority");

                if (string.IsNullOrEmpty(ClientId)) throw new NullReferenceException("ClientId");

                if (SigningMethod == SigningMethod.None && string.IsNullOrEmpty(ClientSecret))
                    throw new NullReferenceException("ClientSecret");

                if (SigningMethod == SigningMethod.X509EnterpriseSecurityKey &&
                    string.IsNullOrEmpty(CertificateThumbprint))
                    throw new NullReferenceException("CertificateThumprint");

                if (SigningMethod == SigningMethod.RsaSecurityKey && !RSAKeyGenerator.KeyExists(ClientId))
                    throw new NullReferenceException("No RSA key found");

                if (string.IsNullOrEmpty(RedirectUri)) throw new NullReferenceException("RedirectUri");
            }
            catch
            {
                if (throwException)
                    throw;
                return false;
            }

            return true;
        }
    }
}