package org.jahia.modules.saml2.admin;

import java.io.IOException;
import javax.jcr.RepositoryException;
import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class SAML2Settings {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2Settings.class);

    private boolean enabled;
    private String siteKey;
    private String identityProviderPath;
    private String relyingPartyIdentifier;
    private String incomingTargetUrl;
    private String spMetaDataLocation;
    private String keyStoreLocation;
    private String keyStorePass;
    private String privateKeyPass;
    private String postLoginPath;

    /**
     * @param siteKey
     * @throws IOException
     */
    public SAML2Settings(final String siteKey) throws IOException {
        this.siteKey = siteKey;
        this.enabled = true;
    }

    /**
     *
     */
    public void remove() {
        try {
            // store settings
            JCRTemplate.getInstance().doExecuteWithSystemSession(new JCRCallback<Boolean>() {
                public Boolean doInJCR(final JCRSessionWrapper session) throws RepositoryException {
                    final JCRNodeWrapper settingsNode = session
                            .getNode("/sites/" + siteKey + "/" + SAML2Constants.SETTINGS_NODE_NAME);
                    settingsNode.remove();
                    session.save();
                    return Boolean.TRUE;
                }
            });
        } catch (RepositoryException e) {
            LOGGER.error("Error deleting context server settings into the repository.", e);
        }
    }

    /**
     * @return
     */
    public boolean load() {
        try {
            // read default settings
            final Boolean defaultSettingLoaded = JCRTemplate.getInstance()
                    .doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, new JCRCallback<Boolean>() {
                        public Boolean doInJCR(final JCRSessionWrapper session) throws RepositoryException {
                            if (session.nodeExists("/sites/" + siteKey)
                                    && session.nodeExists("/sites/" + siteKey + "/" + SAML2Constants.SETTINGS_NODE_NAME)) {
                                final JCRNodeWrapper settingsNode = session
                                        .getNode("/sites/" + siteKey + "/" + SAML2Constants.SETTINGS_NODE_NAME);

                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_IDENTITY_PROVIDER_URL)) {
                                    identityProviderPath = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_IDENTITY_PROVIDER_URL).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_RELYING_PARTY_IDENTIFIER)) {
                                    relyingPartyIdentifier = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_RELYING_PARTY_IDENTIFIER).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_INCOMMING_TARGET_URL)) {
                                    incomingTargetUrl = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_INCOMMING_TARGET_URL).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_SP_META_DATA_LOCATION)) {
                                    spMetaDataLocation = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_SP_META_DATA_LOCATION).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_KEY_STORE_LOCATION)) {
                                    keyStoreLocation = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_KEY_STORE_LOCATION).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_PRIVATE_KEY_PASS)) {
                                    privateKeyPass = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_PRIVATE_KEY_PASS).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_KEY_STORE_PASS)) {
                                    keyStorePass = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_KEY_STORE_PASS).getString();
                                }
                                if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_POST_LOGIN_PATH)) {
                                    postLoginPath = settingsNode
                                            .getProperty(SAML2Constants.SETTINGS_SAML2_POST_LOGIN_PATH).getString();
                                }
                                return true;
                            }
                            return false;
                        }
                    });

            return defaultSettingLoaded;
        } catch (RepositoryException e) {
            LOGGER.error("Error reading settings from the repository.", e);
        }
        return false;
    }

    /**
     *
     */
    public void store() {
        try {
            // store default props
            JCRTemplate.getInstance()
                    .doExecuteWithSystemSessionAsUser(null, Constants.EDIT_WORKSPACE, null, new JCRCallback<Boolean>() {
                        public Boolean doInJCR(final JCRSessionWrapper session) throws RepositoryException {
                            final JCRNodeWrapper settingsNode;
                            if (session.nodeExists("/sites/" + siteKey + "/" + SAML2Constants.SETTINGS_NODE_NAME)) {
                                settingsNode = session.getNode("/sites/" + siteKey + "/" + SAML2Constants.SETTINGS_NODE_NAME);
                            } else {
                                settingsNode = session.getNode("/sites/" + siteKey).addNode(SAML2Constants.SETTINGS_NODE_NAME,
                                        SAML2Constants.SETTINGS_NODE_TYPE);
                            }

                            boolean doSave = setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_IDENTITY_PROVIDER_URL,
                                    getIdentityProviderPath());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_RELYING_PARTY_IDENTIFIER,
                                    getRelyingPartyIdentifier());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_INCOMMING_TARGET_URL,
                                    getIncomingTargetUrl());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_SP_META_DATA_LOCATION,
                                    getSpMetaDataLocation());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_KEY_STORE_LOCATION,
                                    getKeyStoreLocation());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_KEY_STORE_PASS,
                                    getKeyStorePass());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_PRIVATE_KEY_PASS,
                                    getPrivateKeyPass());
                            doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_POST_LOGIN_PATH,
                                    getPostLoginPath());

                            if (doSave) {
                                session.save();
                            }
                            return Boolean.TRUE;
                        }
                    });
        } catch (RepositoryException e) {
            LOGGER.error("Error storing settings into the repository.", e);
        }
    }

    /**
     * @param node
     * @param propertyName
     * @param value
     * @return
     * @throws RepositoryException
     */
    private boolean setProperty(final JCRNodeWrapper node,
            final String propertyName,
            final String value) throws RepositoryException {
        if ((!node.hasProperty(propertyName) && StringUtils.isNotEmpty(value))
                || (node.hasProperty(propertyName)
                && !StringUtils.equals(node.getProperty(propertyName).getString(), value))) {
            if (StringUtils.isEmpty(value)) {
                node.getProperty(propertyName).remove();
            } else {
                node.setProperty(propertyName, value);
            }
            return true;
        }
        return false;
    }

    public String getIdentityProviderPath() {
        return identityProviderPath;
    }

    public void setIdentityProviderPath(final String identityProviderPath) {
        this.identityProviderPath = identityProviderPath;
    }

    public String getRelyingPartyIdentifier() {
        return relyingPartyIdentifier;
    }

    public void setRelyingPartyIdentifier(final String relyingPartyIdentifier) {
        this.relyingPartyIdentifier = relyingPartyIdentifier;
    }

    public String getIncomingTargetUrl() {
        return incomingTargetUrl;
    }

    public void setIncomingTargetUrl(final String incomingTargetUrl) {
        this.incomingTargetUrl = incomingTargetUrl;
    }

    public String getSpMetaDataLocation() {
        return spMetaDataLocation;
    }

    public void setSpMetaDataLocation(final String spMetaDataLocation) {
        this.spMetaDataLocation = spMetaDataLocation;
    }

    public String getKeyStoreLocation() {
        return keyStoreLocation;
    }

    public void setKeyStoreLocation(final String keyStoreLocation) {
        this.keyStoreLocation = keyStoreLocation;
    }

    public String getKeyStorePass() {
        return keyStorePass;
    }

    public void setKeyStorePass(final String keyStorePass) {
        this.keyStorePass = keyStorePass;
    }

    public String getPrivateKeyPass() {
        return privateKeyPass;
    }

    public void setPrivateKeyPass(final String privateKeyPass) {
        this.privateKeyPass = privateKeyPass;
    }

    public boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public String getPostLoginPath() {
        return postLoginPath;
    }

    public void setPostLoginPath(String postLoginPath) {
        this.postLoginPath = postLoginPath;
    }

}
