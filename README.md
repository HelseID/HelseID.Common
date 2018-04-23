# HelseID.Common

## HelseIdClient

The HelseIdClient is a specialized client used to handle the extensions made on IdentityServer by HelseId. It consists of an implementation of the client assertions by use of RSA-keys or Enterprise Certificates. And an implementaition of the token exchange grant type which HelseId supports. 

If one only need standard OAuth and OIDC functionality it is recomended to use the standard clients such as IdentityModel.OidcClient and IdentityModel.Client.TokenClient as they provide this functinality and the HelseIdClient uses these internaly anyway.

```CSharp
Task<LoginResult> Login();
Task<TokenResponse> ClientCredentialsSignIn();
Task<TokenResponse> AcquireTokenByAuthorizationCodeAsync(string code);
Task<TokenResponse> AcquireTokenByRefreshToken(string refreshToken);
Task<TokenResponse> TokenExchange(string accessToken);
```
## HelseIdClientOptions
```CSharp
public string CertificateThumbprint { get; set; }
public SigningMethod SigningMethod { get; set; }
public string PreselectIdp { get; set; }

public string ClientId { get; set; }
public string ClientSecret { get; set; }
public string Scope { get; set; }
public string RedirectUri { get; set; }
public string PostLogoutRedirectUri { get; set; }
public AuthenticationFlow Flow { get; set; };
```


## DCR-Client

HelseID provides an API for setting up configuration for Clients and ApiResources. In order to use this API on need a client configuration with the **helseid://scopes/client/dcr** scope. The API is available through the swagger specification on http://helseid-dcr.nhn.no/swagger/ and we recomend using a swagger-generator to create and maintain



##
