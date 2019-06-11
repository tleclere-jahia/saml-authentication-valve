package org.jahia.modules.saml2;

public class SAML2Constants {
    public static final String ENABLED = "enabled";
    public static final String IDENTITY_PROVIDER_URL = "identityProviderPath";
    public static final String RELYING_PARTY_IDENTIFIER = "relyingPartyIdentifier";
    public static final String INCOMING_TARGET_URL = "incomingTargetUrl";
    public static final String SP_META_DATA_LOCATION = "spMetaDataLocation";
    public static final String KEY_STORE_LOCATION = "keyStoreLocation";
    public static final String KEY_STORE_PASS = "keyStorePass";
    public static final String PRIVATE_KEY_PASS = "privateKeyPass";
    public static final String SITE = "site";


    public static final String SETTINGS_NODE_NAME = "saml2-settings";
    public static final String SETTINGS_NODE_TYPE = "saml2nt:settings";
    public static final String SETTINGS_SAML2_IDENTITY_PROVIDER_URL = "saml2:identityProviderPath";
    public static final String SETTINGS_SAML2_RELYING_PARTY_IDENTIFIER = "saml2:relyingPartyIdentifier";
    public static final String SETTINGS_SAML2_INCOMMING_TARGET_URL = "saml2:incomingTargetUrl";
    public static final String SETTINGS_SAML2_SP_META_DATA_LOCATION = "saml2:spMetaDataLocation";
    public static final String SETTINGS_SAML2_KEY_STORE_LOCATION = "saml2:keyStoreLocation";
    public static final String SETTINGS_SAML2_KEY_STORE_PASS = "saml2:keyStorePass";
    public static final String SETTINGS_SAML2_PRIVATE_KEY_PASS = "saml2:privateKeyPass";
    public static final String SETTINGS_SAML2_POST_LOGIN_PATH = "loginSuccessPath";

    public static final String SAML2_USER_PROPERTY_EMAIL = "Email";
    public static final String SAML2_USER_PROPERTY_FIRSTNAME = "First Name";
    public static final String SAML2_USER_PROPERTY_LASTNAME = "Last Name";

    public static String serverName;
    public static String siteKey;

    public static void setServerName(String serverName) {
        SAML2Constants.serverName = serverName;
    }

    public static void setSiteKey(String siteKey) {
        SAML2Constants.siteKey = siteKey;
    }
}
