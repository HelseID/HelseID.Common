# HelseID.Common

The HelseID.Common repo consists of code to help developers use the extended functionality of HelseID. It is means to be used for inspiration for how to solve some of the more technical aspects, but should not be used uncritically as is. A description of the key components follows:

## Clients

The HelseIdClient is a specialized client used to handle the extensions made on IdentityServer by HelseId. It consists of an implementation of the client assertions by use of RSA-keys or Enterprise Certificates. And in addition an implementaition of the token exchange grant type which HelseId supports.

If one only need standard OAuth and OIDC functionality it is recomended to use the standard clients such as IdentityModel.OidcClient and IdentityModel.Client.TokenClient as they provide the needed functinality ( HelseIdClient uses these internaly).

## Browser

A OAuth/OIDC-client needs to interact with a browser in order to do an authentication. This folder consists of implementations to handle these interactions with both a system browser or an embedded browser.

## Certificates

Certificates are one of the signing mechanisms for the client assertion. The certificate store implementations helps with extracting a certificate for the windows certificate store based on a thumbprint.

## Crypto

RSA keys are another signing mechanism for the client assertion. The RSAKeyGenerator helps with the management of generating and storing a RSA key.

## Extensions

Helper functionality for common operations on RSAKeys, strings and tokens.

## Client Assertion

Contains the model for creating a client assertion jwt with the required claims.

## Network

Helper functionality related to networking. Such as availability checks for endpoints.



