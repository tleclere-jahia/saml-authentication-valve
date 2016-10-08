/**
 * ==========================================================================================
 * =                            JAHIA'S ENTERPRISE DISTRIBUTION                             =
 * ==========================================================================================
 * <p>
 * http://www.jahia.com
 * <p>
 * JAHIA'S ENTERPRISE DISTRIBUTIONS LICENSING - IMPORTANT INFORMATION
 * ==========================================================================================
 * <p>
 * Copyright (C) 2002-2016 Jahia Solutions Group. All rights reserved.
 * <p>
 * This file is part of a Jahia's Enterprise Distribution.
 * <p>
 * Jahia's Enterprise Distributions must be used in accordance with the terms
 * contained in the Jahia Solutions Group Terms & Conditions as well as
 * the Jahia Sustainable Enterprise License (JSEL).
 * <p>
 * For questions regarding licensing, support, production usage...
 * please contact our team at sales@jahia.com or go to http://www.jahia.com/license.
 * <p>
 * ==========================================================================================
 */
package org.jahia.modules.saml2.admin;

import com.google.common.io.CharStreams;
import org.apache.commons.lang.StringUtils;
import org.jahia.bin.Action;
import org.jahia.bin.ActionResult;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.URLResolver;
import org.json.JSONException;
import org.json.JSONObject;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.util.List;
import java.util.Map;

public class SAML2SettingsAction extends Action {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsAction.class);
    private SAML2SettingsService saml2SettingsService;

    /**
     *
     * @param request
     * @param renderContext
     * @param resource
     * @param session
     * @param parameters
     * @param urlResolver
     * @return
     * @throws Exception
     */
    @Override
    public ActionResult doExecute(final HttpServletRequest request,
                                  final RenderContext renderContext,
                                  final Resource resource,
                                  final JCRSessionWrapper session, Map<String, List<String>> parameters,
                                  final URLResolver urlResolver) throws Exception {
        try {
            final String responseText = CharStreams.toString(request.getReader());
            final JSONObject settings;
            final SAML2Settings serverSettings;
            final String siteKey = renderContext.getSite().getSiteKey();
            // if payload has content, it means an update.
            if (StringUtils.isNotEmpty(responseText)) {
                settings = new JSONObject(responseText);
                final SAML2Settings oldSettings = saml2SettingsService.getSettings(siteKey);
                final Boolean enabled = getSettingOrDefault(settings, SAML2Constants.ENABLED,
                        (oldSettings != null && oldSettings.getEnabled()));
                final String identityProviderUrl = getSettingOrDefault(settings, SAML2Constants.IDENTITY_PROVIDER_URL,
                        (oldSettings != null ? oldSettings.getIdentityProviderUrl() : ""));
                final String relyingPartyIdentifier = getSettingOrDefault(settings, SAML2Constants.RELYING_PARTY_IDENTIFIER,
                        (oldSettings != null ? oldSettings.getRelyingPartyIdentifier() : ""));
                final String incomingTargetUrl = getSettingOrDefault(settings, SAML2Constants.INCOMING_TARGET_URL,
                        (oldSettings != null ? oldSettings.getIncomingTargetUrl() : ""));
                final String spMetaDataLocation = getSettingOrDefault(settings, SAML2Constants.SP_META_DATA_LOCATION,
                        (oldSettings != null ? oldSettings.getSpMetaDataLocation() : ""));
                final String keyStoreLocation = getSettingOrDefault(settings, SAML2Constants.KEY_STORE_LOCATION,
                        (oldSettings != null ? oldSettings.getKeyStoreLocation() : ""));
                final String keyStorePass = getSettingOrDefault(settings, SAML2Constants.KEY_STORE_PASS,
                        (oldSettings != null ? oldSettings.getKeyStorePass() : ""));
                final String privateKeyPass = getSettingOrDefault(settings, SAML2Constants.PRIVATE_KEY_PASS,
                        (oldSettings != null ? oldSettings.getPrivateKeyPass() : ""));
                if (enabled) {
                    serverSettings = saml2SettingsService.setSAML2Settings(siteKey,
                            identityProviderUrl, relyingPartyIdentifier, incomingTargetUrl,
                            spMetaDataLocation, keyStoreLocation, keyStorePass, privateKeyPass);
                } else {
                    serverSettings = null;
                }
            } else {
                serverSettings = saml2SettingsService.getSettings(siteKey);
            }

            final JSONObject resp = new JSONObject();
            if (serverSettings != null) {
                resp.put(SAML2Constants.ENABLED, serverSettings.getEnabled());
                resp.put(SAML2Constants.IDENTITY_PROVIDER_URL, serverSettings.getIdentityProviderUrl());
                resp.put(SAML2Constants.RELYING_PARTY_IDENTIFIER, serverSettings.getRelyingPartyIdentifier());
                resp.put(SAML2Constants.INCOMING_TARGET_URL, serverSettings.getIncomingTargetUrl());
                resp.put(SAML2Constants.SP_META_DATA_LOCATION, serverSettings.getSpMetaDataLocation());
                resp.put(SAML2Constants.KEY_STORE_LOCATION, serverSettings.getKeyStoreLocation());
                resp.put(SAML2Constants.KEY_STORE_PASS, serverSettings.getKeyStorePass());
                resp.put(SAML2Constants.PRIVATE_KEY_PASS, serverSettings.getPrivateKeyPass());
            }
            resp.put("noConf", serverSettings == null);
            return new ActionResult(HttpServletResponse.SC_OK, null, resp);
        } catch (Exception e) {
            JSONObject error = new JSONObject();
            if (LOGGER.isDebugEnabled()) {
                LOGGER.debug("error while saving settings", e);
            }
            error.put("error", e.getMessage());
            error.put("type", e.getClass().getSimpleName());
            return new ActionResult(HttpServletResponse.SC_INTERNAL_SERVER_ERROR, null, error);
        }
    }

    /**
     *
     * @param settings
     * @param propertyName
     * @param defaultValue
     * @param <T>
     * @return
     * @throws JSONException
     */
    private <T> T getSettingOrDefault(final JSONObject settings,
                                      final String propertyName,
                                      final T defaultValue) throws JSONException {
        return settings.has(propertyName) ? (T) settings.get(propertyName) : defaultValue;
    }

    /**
     *
     * @param saml2SettingsService
     */
    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }
}
