# SAML Authentication Valve #
This POC authentication valve is set up to connect to a Shibboleth IDP.  This authentication valve is not supported by Jahia.  Use at your own risk.

##Self Signed Certifcates
Create the certificates, keys, and keystore in the `${java.home}/jre/lib/security/`.  This should only used for **non production** environments.

- **keypass**: Password to protect the private key
- **storepass**: Password to protect the key store

**Note** `keytool` is available as part of the Java package. 

###Jahia (Service Provider) Key Store
Create a keystore that will contain the sertificate and key to be used when signing and encrypting the SAML2 authentication request.  The private key will be used to decrypt the SAML2 assertion response.
```
keytool -genkeypair -alias pac4j-demo -keypass ${keypass} -keystore sp.jks -storepass ${storepass} -keyalg RSA -keysize 2048 -validity 3650
```
####Important Input Step
- What is your first and last name?: `idp.jahia.local`

###IDP Certificate and Key
Create a certificate and private key to be used for SSL protocol transmission to the IDP.

```
openssl req -new -newkey rsa:2048 -nodes -keyout idp.key -out idp.csr
openssl x509 -req -days 365 -in idp.csr -signkey idp.key -out idp.crt
```
Add this certificate to the Java key store.
```
keytool -keystore cacerts -importcert -alias idp -file idp.crt
```

####Important Input Step
- Common Name (eg, your name or your server's hostname): `https://sp.jahia.org/shibboleth-sp`

###Jahia Certificate and Key
Create a certificate and private key to be used for SSL protocol transmission to Jahia DX.

```
openssl req -new -newkey rsa:2048 -nodes -keyout jahia.key -out jahia.csr
openssl x509 -req -days 365 -in jahia.csr -signkey jahia.key -out jahia.crt
```
Add this certificate to the Java key store.
```
keytool -keystore cacerts -importcert -alias jahia -file jahia.crt
```

####Important Input Step
- Common Name (eg, your name or your server's hostname): `jahia.local`

###List Certificates in Java Key Store
```
keytool -list -keystore cacerts
```
