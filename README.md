# SAML Authentication Valve #
This POC authentication valve is set up to connect to a Shibboleth IDP.  This authentication valve is not supported by Jahia.  Use at your own risk.

##I / Self Signed Certifcates generation for the Service Provider (Jahia)
Create the certificates, keys, and keystore in the `${java.home}/jre/lib/security/`.  This should only used for **non production** environments.

- **keypass**: Password to protect the private key
- **storepass**: Password to protect the key store

**Note** `keytool` is available as part of the Java package. 

### 1. Key Store Generation

Create a keystore that will contain the certificate and key to be used when signing and encrypting the SAML2 authentication request.  The private key will be used to decrypt the SAML2 assertion response.
```
keytool -genkeypair -alias pac4j-demo -keypass ${keypass} -keystore sp.jks -storepass ${storepass} -keyalg RSA -keysize 2048 -validity 3650
```

#####Important Input Step
- What is your first and last name?: `jahia.server.name`

**This value must match your Jahia site domain name**

### 2. Private Key Generation
Create a private key to be used for SSL protocol transmission to Jahia DX.

```
openssl req -new -newkey rsa:2048 -nodes -keyout jahia.key -out jahia.csr
```
####Important Input Step

- Common Name (eg, your name or your server's hostname): `jahia.sp.id`

**This value is arbitrary and will be our “Relying Party Identifier”**


### 3. Certificate Generation
Create a certificate to be used for SSL protocol transmission to Jahia DX.

```
openssl x509 -req -days 365 -in jahia.csr -signkey jahia.key -out jahia.crt
```

### 4. Adding the certification to the keystore

The keystore password should be the same as defined in the key store generation

```
keytool -keystore cacerts -importcert -alias jahia -file jahia.crt
```

### 5-  Verification by listing certificates in Java Key Store

The newly created certificate should be listed when running this command

```
keytool -list -keystore cacerts
```

##II / Valve Configuration

###local path of the Identity Provider MetaData file
The IPD Metadata file is provided by the IDP. This XML file must be uploaded on the Jahia server and its path must be provided in this field

###local path of the generated Service Provider MetaData file
This is where, during the first login attempt we will generate our SP Metadata File. This file has to be retrieve and sent to the IDP.

###Relying Party Identifier
The value is arbitrary and has been defined when generating the private key.

###Incoming Target Url
This is the URL when the Idp will return the SAML response. Its default value is /cms/login.SAML.incoming

###Key Store Pass and Private Key Pass
Those value must match the one defined when creating the server key and certificate.
