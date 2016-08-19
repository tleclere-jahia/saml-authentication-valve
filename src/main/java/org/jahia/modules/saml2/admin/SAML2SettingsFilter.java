/**
 * ==========================================================================================
 * =                            JAHIA'S ENTERPRISE DISTRIBUTION                             =
 * ==========================================================================================
 *
 *                                  http://www.jahia.com
 *
 * JAHIA'S ENTERPRISE DISTRIBUTIONS LICENSING - IMPORTANT INFORMATION
 * ==========================================================================================
 *
 *     Copyright (C) 2002-2016 Jahia Solutions Group. All rights reserved.
 *
 *     This file is part of a Jahia's Enterprise Distribution.
 *
 *     Jahia's Enterprise Distributions must be used in accordance with the terms
 *     contained in the Jahia Solutions Group Terms & Conditions as well as
 *     the Jahia Sustainable Enterprise License (JSEL).
 *
 *     For questions regarding licensing, support, production usage...
 *     please contact our team at sales@jahia.com or go to http://www.jahia.com/license.
 *
 * ==========================================================================================
 */
package org.jahia.modules.saml2.admin;

import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.filter.AbstractFilter;
import org.jahia.services.render.filter.RenderChain;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

/**
 * @author kevan
 */
public class SAML2SettingsFilter extends AbstractFilter {
    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsFilter.class);
    private SAML2SettingsService saml2SettingsService;

    @Override
    public String prepare(final RenderContext renderContext,
                          final Resource resource,
                          final RenderChain chain) throws Exception {

        final SAML2Settings saml2Settings = saml2SettingsService.getSettings(renderContext.getSite().getSiteKey());
        renderContext.getRequest().setAttribute("saml2HasSettings", saml2Settings != null);

        final String language = renderContext.getUILocale().getLanguage();
        if (LOGGER.isDebugEnabled()) {
            LOGGER.debug("langugage is {}", language);
        }
        if (saml2SettingsService.getResourceBundleName() != null) {
            renderContext.getRequest().setAttribute("i18nJavaScriptFile", "i18n/" + saml2SettingsService.getResourceBundleName() +
                    (saml2SettingsService.getSupportedLocales().contains(language) ? ("_" + language) : "") + ".js");
        }
        return null;
    }

    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }
}
