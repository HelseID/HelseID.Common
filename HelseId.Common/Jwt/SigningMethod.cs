namespace HelseId.Common.Jwt
{
    public partial class JwtGenerator
    {
        public enum SigningMethod
        {
            None,
            X509SecurityKey,
            RsaSecurityKey,
            X509EnterpriseSecurityKey
        }
    }
}