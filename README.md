# SAML Authentication Valve
This community module (not supported by Jahia) is meant to activate SAML on one or multiples Jahia websites.


### 1. Keystore Generation

Create a keystore: 
```sh
keytool -genkeypair -alias jahiakeystorealias -keypass changeit_privatekey -keystore sp.jks -storepass changeit_keystore -keyalg RSA -keysize 2048 -validity 3650
```

#### :warning: Important Input Step :warning:
- What is your first and last name?: ***jahia.server.name***

***This value must match your Jahia site domain name***

  then upload it in your website thanks to the Document manager and publish it.
  
## Valve Configuration

#### Path in the JCR of the Identity Provider MetaData file
The Identity Provider Metadata file is provided by the Identity Provider (IdP), for example Shibboleth or Google. This XML file must be uploaded and published in Jahia thanks to the Document Manager.

#### Path on the server of the Service Provider Metadata file (where it will be generated)
This is where, during the first login attempt we will generate our SP Metadata File. This file has to be retrieved and sent to the IDP. You can also access this XML file thanks to the URL WEBSITE_URL/home.metadata.do

#### Relying Party Identifier
The value is arbitrary.

#### Incoming Target Url
This is the URL when the Idp will return the SAML response. Its default value is /cms/login.SAML.incoming

#### Path in the JCR of the Keystore, Password of the Keystore and Password of the Private Key
Those value must match the one defined when creating the server key and certificate.

#### Redirect after successful login
This is the DX relative ULR where the user will be redirect after successfully authentication.

## Configuration example

- Path in the JCR of the Identity Provider MetaData file:`/sites/mySite/files/saml/GoogleIDPMetadata-jahia.com.xml`
- Local path of the generated Service Provider MetaData file:
`/tmp/sp.metadata.xml`
- Relying Party Identifier: `test.jahia.com`
- Incoming Target Url:`/cms/login.SAML.incoming`
- Password of the Private Key:`/sites/mySite/files/saml/sp.jks`
- Key Store Pass:`changeit_keystore`
- Private Key Pass:`changeit_privatekey`
- Redirect ath sfter successful login:`/home.html`
