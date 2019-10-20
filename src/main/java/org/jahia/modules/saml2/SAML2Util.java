package org.jahia.modules.saml2;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import org.apache.commons.lang.StringUtils;
import org.jahia.modules.saml2.admin.SAML2Settings;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
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
            initSAMLClient(saml2Settings, request);
        }
        return client;
    }

    /**
     * New method to Initializing saml client.
     *
     * @param saml2Settings
     * @param request
     */
    private static void initSAMLClient(SAML2Settings saml2Settings, HttpServletRequest request) {
        // TODO: refactor code to get a method to generation the SAML2ClientConfiguration object
        final SAML2ClientConfiguration saml2ClientConfiguration = new SAML2ClientConfiguration();
        // TODO: add this parameter to the valve configuration in the JCR
        saml2ClientConfiguration.setMaximumAuthenticationLifetime(18000);
        // TODO: set the IdentityProviderMetadata file from the JCR
        saml2ClientConfiguration.setIdentityProviderMetadataPath(saml2Settings.getIdentityProviderPath());
        saml2ClientConfiguration.setServiceProviderEntityId(saml2Settings.getRelyingPartyIdentifier());
        // TODO: set the Keystore file from the JCR
        saml2ClientConfiguration.setKeystorePath(saml2Settings.getKeyStoreLocation());
        saml2ClientConfiguration.setKeystorePassword(saml2Settings.getKeyStorePass());
        saml2ClientConfiguration.setPrivateKeyPassword(saml2Settings.getPrivateKeyPass());
        // TODO: set the ServiceProviderMetadata file from the JCR
        saml2ClientConfiguration.setServiceProviderMetadataPath(saml2Settings.getSpMetaDataLocation());

        client = new SAML2Client(saml2ClientConfiguration);
        client.setCallbackUrl(SAML2Util.getAssertionConsumerServiceUrl(request, saml2Settings.getIncomingTargetUrl()));
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
}
