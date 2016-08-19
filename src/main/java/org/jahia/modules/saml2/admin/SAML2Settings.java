package org.jahia.modules.saml2.admin;

import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.jcr.RepositoryException;
import java.io.IOException;

/**
 * Created by smomin on 8/18/16.
 */
public class SAML2Settings {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2Settings.class);

    private String siteKey;
    private boolean enabled;
    private String identityProviderUrl;
    private String relyingPartyIdentifier;
    private String incomingTargetUrl;
    private String idpMetaDataLocation;
    private String signingCertLocation;
    private String encryptionCertLocation;

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
                            identityProviderUrl = settingsNode
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
                        if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_IDP_METADATA_LOCATION)) {
                            idpMetaDataLocation = settingsNode
                                    .getProperty(SAML2Constants.SETTINGS_SAML2_IDP_METADATA_LOCATION).getString();
                        }
                        if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_SIGNING_CERT_LOCATION)) {
                            signingCertLocation = settingsNode
                                    .getProperty(SAML2Constants.SETTINGS_SAML2_SIGNING_CERT_LOCATION).getString();
                        }
                        if (settingsNode.hasProperty(SAML2Constants.SETTINGS_SAML2_ENCRYPTION_CERT_LOCATION)) {
                            encryptionCertLocation = settingsNode
                                    .getProperty(SAML2Constants.SETTINGS_SAML2_ENCRYPTION_CERT_LOCATION).getString();
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
                            getIdentityProviderUrl());
                    doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_RELYING_PARTY_IDENTIFIER,
                            getRelyingPartyIdentifier());
                    doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_INCOMMING_TARGET_URL,
                            getIncomingTargetUrl());
                    doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_IDP_METADATA_LOCATION,
                            getIdpMetaDataLocation());
                    doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_ENCRYPTION_CERT_LOCATION,
                            getEncryptionCertLocation());
                    doSave |= setProperty(settingsNode, SAML2Constants.SETTINGS_SAML2_SIGNING_CERT_LOCATION,
                            getSigningCertLocation());

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

    public String getIdentityProviderUrl() {
        return identityProviderUrl;
    }

    public void setIdentityProviderUrl(final String identityProviderUrl) {
        this.identityProviderUrl = identityProviderUrl;
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

    public String getIdpMetaDataLocation() {
        return idpMetaDataLocation;
    }

    public void setIdpMetaDataLocation(final String idpMetaDataLocation) {
        this.idpMetaDataLocation = idpMetaDataLocation;
    }

    public boolean getEnabled() {
        return enabled;
    }

    public void setEnabled(final boolean enabled) {
        this.enabled = enabled;
    }

    public String getSigningCertLocation() {
        return signingCertLocation;
    }

    public void setSigningCertLocation(final String signingCertLocation) {
        this.signingCertLocation = signingCertLocation;
    }

    public String getEncryptionCertLocation() {
        return encryptionCertLocation;
    }

    public void setEncryptionCertLocation(final String encryptionCertLocation) {
        this.encryptionCertLocation = encryptionCertLocation;
    }
}
