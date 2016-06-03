package org.jahia.modules.saml2.valve;

import org.opensaml.Configuration;
import org.opensaml.xml.XMLObjectBuilderFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.xml.namespace.QName;

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

}
