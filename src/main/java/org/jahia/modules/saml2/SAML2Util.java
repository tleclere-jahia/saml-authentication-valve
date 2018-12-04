package org.jahia.modules.saml2;

import org.apache.commons.lang.StringUtils;
import org.jahia.modules.saml2.admin.SAML2Settings;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.opensaml.core.config.InitializationService;
import org.pac4j.core.util.CommonHelper;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.client.SAML2ClientConfiguration;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;

/**
 * Created by smomin on 5/27/16.
 */
public class SAML2Util {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2Util.class);

    /**
     * @param request
     * @return
     */
    public static String getAssertionConsumerServiceUrl(final HttpServletRequest request,
                                                        final String incoming) {
        final StringBuilder url = new StringBuilder();
        String serverName = request.getHeader("X-Forwarded-Server");
        if (StringUtils.isEmpty(serverName)) {
            serverName = request.getServerName();
        }
        url.append("https://").append(serverName);

        return "https://" + serverName + incoming;
    }

    /**
     *
     */
    public static void initialize(final SAML2CallBack callBack) {
        // adapt TCCL
        final Thread thread = Thread.currentThread();
        final ClassLoader loader = thread.getContextClassLoader();
        thread.setContextClassLoader(InitializationService.class.getClassLoader());
        try {
            InitializationService.initialize();
            callBack.execute();
        } catch (Exception e) {
            LOGGER.error(e.getMessage(), e);
        } finally {
            // reset TCCL
            thread.setContextClassLoader(loader);
        }
    }

    /**
     * @param saml2SettingsService
     * @param request
     * @return
     */
    public static SAML2Client getSAML2Client(final SAML2SettingsService saml2SettingsService,
                                             final HttpServletRequest request) {
        final SAML2Settings saml2Settings = saml2SettingsService.getSettings(getCookieValue(request, SAML2Constants.SITE));
        final SAML2ClientConfiguration saml2ClientConfiguration = new SAML2ClientConfiguration();
        saml2ClientConfiguration.setIdentityProviderMetadataPath(saml2Settings.getIdentityProviderPath());
        saml2ClientConfiguration.setServiceProviderEntityId(saml2Settings.getRelyingPartyIdentifier());
        saml2ClientConfiguration.setKeystoreResource(CommonHelper.getResource(saml2Settings.getKeyStoreLocation()));
        saml2ClientConfiguration.setKeystorePassword(saml2Settings.getKeyStorePass());
        saml2ClientConfiguration.setPrivateKeyPassword(saml2Settings.getPrivateKeyPass());
        saml2ClientConfiguration.setServiceProviderMetadataPath(saml2Settings.getSpMetaDataLocation());

        final SAML2Client client = new SAML2Client(saml2ClientConfiguration);
        client.setCallbackUrl(SAML2Util.getAssertionConsumerServiceUrl(request, saml2Settings.getIncomingTargetUrl()));
        return client;
    }


    /**
     * @param request
     */
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

}
