package org.jahia.modules.saml2.admin;

import java.io.IOException;
import java.util.Collections;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;
import javax.jcr.RepositoryException;
import org.apache.commons.lang.StringUtils;
import org.jahia.data.templates.JahiaTemplatesPackage;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.jahia.services.content.decorator.JCRSiteNode;
import org.jahia.services.sites.JahiaSitesService;
import org.jahia.services.templates.JahiaModuleAware;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.beans.factory.InitializingBean;

public final class SAML2SettingsService implements InitializingBean, JahiaModuleAware {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsService.class);
    private static final SAML2SettingsService INSTANCE = new SAML2SettingsService();
    private Map<String, SAML2Settings> settingsBySiteKeyMap = new HashMap<>();
    private String resourceBundleName;
    private JahiaTemplatesPackage module;
    private Set<String> supportedLocales = Collections.emptySet();

    private SAML2SettingsService() {
        super();
    }

    public static SAML2SettingsService getINSTANCE() {
        return INSTANCE;
    }

    public void loadSettings(final String siteKey) throws RepositoryException {
        JCRTemplate.getInstance().doExecuteWithSystemSession(new JCRCallback<Object>() {
            
            @Override
            public Object doInJCR(final JCRSessionWrapper session) throws RepositoryException {
                //clean up
                if (siteKey == null) {
                    settingsBySiteKeyMap.clear();
                    for (final JCRSiteNode siteNode : JahiaSitesService.getInstance().getSitesNodeList(session)) {
                        loadSettings(siteNode);
                    }
                } else {
                    settingsBySiteKeyMap.remove(siteKey);
                    if (session.nodeExists("/sites/" + siteKey)) {
                        loadSettings(JahiaSitesService.getInstance().getSiteByKey(siteKey, session));
                    }
                }
                return null;
            }

            private void loadSettings(final JCRSiteNode siteNode) throws RepositoryException {
                boolean loaded;
                try {
                    final SAML2Settings settings = new SAML2Settings(siteNode.getSiteKey());
                    loaded = settings.load();
                    if (loaded) {
                        settingsBySiteKeyMap.put(siteNode.getSiteKey(), settings);
                    }
                } catch (Exception e) {
                    LOGGER.error("Error while loading settings from "
                            + siteNode.getPath() + "/"
                            + SAML2Constants.SETTINGS_NODE_NAME, e);
                }
            }
        });
    }

    public SAML2Settings setSAML2Settings(final String siteKey,
            final String identityProviderPath,
            final String relyingPartyIdentifier,
            final String incomingTargetUrl,
            final String spMetaDataLocation,
            final String keyStoreLocation,
            final String keyStorePass,
            final String privateKeyPass,
            final String postLoginPath) throws IOException {
        final SAML2Settings settings = new SAML2Settings(siteKey);
        settings.setIdentityProviderPath(identityProviderPath);
        settings.setRelyingPartyIdentifier(relyingPartyIdentifier);
        settings.setIncomingTargetUrl(incomingTargetUrl);
        settings.setSpMetaDataLocation(spMetaDataLocation);
        settings.setKeyStoreLocation(keyStoreLocation);
        settings.setKeyStorePass(keyStorePass);
        settings.setPrivateKeyPass(privateKeyPass);
        settings.setPostLoginPath(postLoginPath);

        // refresh and save settings
        settings.store();

        settingsBySiteKeyMap.put(siteKey, settings);
        return settings;
    }

    public void removeServerSettings(String siteKey) {
        if (settingsBySiteKeyMap.containsKey(siteKey)) {
            settingsBySiteKeyMap.get(siteKey).remove();
            settingsBySiteKeyMap.remove(siteKey);
        }
    }

    public Map<String, SAML2Settings> getSettingsBySiteKeyMap() {
        return settingsBySiteKeyMap;
    }

    public SAML2Settings getSettings(final String siteKey) {
        return settingsBySiteKeyMap.get(siteKey);
    }

    @Override
    public void setJahiaModule(final JahiaTemplatesPackage jahiaTemplatesPackage) {
        this.module = jahiaTemplatesPackage;

        final org.springframework.core.io.Resource[] resources;
        final String rbName = module.getResourceBundleName();
        if (rbName != null) {
            resourceBundleName = StringUtils.substringAfterLast(rbName, ".") + "-i18n";
            resources = module.getResources("javascript/i18n");
            supportedLocales = new HashSet<>();
            for (final org.springframework.core.io.Resource resource : resources) {
                final String f = resource.getFilename();
                if (f.startsWith(resourceBundleName)) {
                    final String l = StringUtils.substringBetween(f, resourceBundleName, ".js");
                    supportedLocales.add(l.length() > 0 ? StringUtils.substringAfter(l, "_") : StringUtils.EMPTY);
                }
            }
        }
    }

    public Set<String> getSupportedLocales() {
        return Collections.unmodifiableSet(supportedLocales);
    }

    public String getResourceBundleName() {
        return resourceBundleName;
    }

    @Override
    public void afterPropertiesSet() throws Exception {
        loadSettings(null);
    }
}
