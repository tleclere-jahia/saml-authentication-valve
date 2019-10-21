package org.jahia.modules.saml2;

import java.io.File;
import javax.jcr.RepositoryException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.saml2.admin.SAML2Settings;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.services.content.JCRCallback;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.JCRTemplate;
import org.opensaml.core.config.InitializationService;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public final class SAML2Util {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2Util.class);
    private static SAML2Client client;

    private SAML2Util() {
    }

    /**
     * SAML Initialization on class level.
     */
    static {
        // adapt TCCL
        final Thread thread = Thread.currentThread();
        final ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());
        try {
            InitializationService.initialize();
        } catch (Exception ex) {
            LOGGER.error("Impossible to initialize", ex);
        } finally {
            // reset TCCL
            thread.setContextClassLoader(loader);
        }
    }

    public static String getAssertionConsumerServiceUrl(final HttpServletRequest request,
            final String incoming) {
        final StringBuilder url = new StringBuilder();
        String serverName = request.getHeader("X-Forwarded-Server");
        if (StringUtils.isEmpty(serverName)) {
            serverName = request.getServerName();
        }
        url.append(request.getScheme()).append("://").append(serverName).append(incoming);

        return url.toString();
    }

    public static void initialize(final SAML2CallBack callBack) {
        // adapt TCCL
        final Thread thread = Thread.currentThread();
        final ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());
        try {
            callBack.execute();
        } catch (Exception ex) {
            LOGGER.error("Impossible to execute the callback", ex);
        } finally {
            // reset TCCL
            thread.setContextClassLoader(loader);
        }
    }

    /**
     * Get saml client.
     *
     * @param saml2SettingsService
     * @param request
     * @return
     */
    public static SAML2Client getSAML2Client(final SAML2SettingsService saml2SettingsService,
            final HttpServletRequest request, String siteKey) {
        final SAML2Settings saml2Settings = saml2SettingsService.getSettings(siteKey);
        if (client == null) {
            initSAMLClient(saml2Settings, request, siteKey);
        }
        return client;
    }

    public static String getCookieValue(final HttpServletRequest request,
            final String name) {
        final Cookie[] cookies = request.getCookies();
        for (final Cookie cookie : cookies) {
            if (cookie.getName().equals(name)) {
                return cookie.getValue();
            }
        }
        return null;
    }

    /**
     * Method to reset SAMLClient so that a new state {@link SAML2Client} can be generated, when it is requested the
     * next time.
     */
    public static void resetClient() {
        client = null;
    }

    public static SAML2ClientConfiguration getSAML2ClientConfiguration(SAML2Settings saml2Settings, String siteKey) {
        final SAML2ClientConfiguration saml2ClientConfiguration = new SAML2ClientConfiguration();

        try {
            JCRTemplate.getInstance().doExecuteWithSystemSession(new JCRCallback<Boolean>() {
                public Boolean doInJCR(final JCRSessionWrapper session) {
                    // TODO: add this parameter to the valve configuration in the JCR
                    saml2ClientConfiguration.setMaximumAuthenticationLifetime(18000);
                    saml2ClientConfiguration.setIdentityProviderMetadataResource(new JCRResource(saml2Settings.getIdentityProviderPath()));
                    saml2ClientConfiguration.setServiceProviderEntityId(saml2Settings.getRelyingPartyIdentifier());
                    saml2ClientConfiguration.setKeystoreResource(new JCRResource(saml2Settings.getKeyStoreLocation()));
                    saml2ClientConfiguration.setKeystorePassword(saml2Settings.getKeyStorePass());
                    saml2ClientConfiguration.setPrivateKeyPassword(saml2Settings.getPrivateKeyPass());
                    saml2ClientConfiguration.setServiceProviderMetadataPath(saml2Settings.getSpMetaDataLocation());
                    return true;
                }
            });
        } catch (RepositoryException ex) {
            LOGGER.error("Impossible to retrieve SAMLK2ClientConfiguration", ex);
        }
        return saml2ClientConfiguration;
    }

    /**
     * New method to Initializing saml client.
     *
     * @param saml2Settings
     * @param request
     */
    private static void initSAMLClient(SAML2Settings saml2Settings, HttpServletRequest request, String siteKey) {
        client = new SAML2Client(getSAML2ClientConfiguration(saml2Settings, siteKey));
        client.setCallbackUrl(SAML2Util.getAssertionConsumerServiceUrl(request, saml2Settings.getIncomingTargetUrl()));
    }
}
