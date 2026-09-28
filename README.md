# CS-CustomCredentialStorePlugin-HashiCorp
The built-in HashiCorp Vault – Read Only store couldn't be used. The customer's credentials had to come through their own HTTP layer: POST /ad-details with an ADFS OAuth2 token (private_key_jwt, signed by an X.509 cert) behind an Envoy gateway. That meant building a custom ISecureStore plugin, which is usually a lot of slow trial and error.
