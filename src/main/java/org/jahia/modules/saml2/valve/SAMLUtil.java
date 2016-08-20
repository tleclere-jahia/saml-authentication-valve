package org.jahia.modules.saml2.valve;

import org.apache.commons.lang.StringUtils;
import org.opensaml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.xml.namespace.QName;

import static org.jahia.modules.saml2.SAML2Constants.SAML_INCOMING;

/**
 * Created by smomin on 5/27/16.
 */
public class SAMLUtil {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAMLUtil.class);

    public static <T> T buildSAMLObjectWithDefaultName(final Class<T> clazz) {

        try {
            final XMLObjectBuilderFactory builderFactory = Configuration.getBuilderFactory();
            final QName defaultElementName = (QName) clazz.getDeclaredField("DEFAULT_ELEMENT_NAME").get(null);
            final T object = (T) builderFactory.getBuilder(defaultElementName).buildObject(defaultElementName);
            return object;
        } catch (IllegalAccessException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (NoSuchFieldException e) {
            LOGGER.error(e.getMessage(), e);
        }
        return null;
    }

    /**
     *
     * @param request
     * @return
     */
    public static String getAssertionConsumerServiceUrl(final HttpServletRequest request) {
        final StringBuilder url = new StringBuilder();
        String serverName = request.getHeader("X-Forwarded-Server");
        if (StringUtils.isEmpty(serverName)) {
            serverName = request.getServerName();
        }
        url.append("https://").append(serverName);

        return "https://" + serverName + "/cms/login" + SAML_INCOMING;
    }

}
