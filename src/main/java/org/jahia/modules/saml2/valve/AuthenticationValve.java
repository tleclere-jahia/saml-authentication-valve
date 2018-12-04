package org.jahia.modules.saml2.valve;

import org.apache.commons.lang.StringUtils;
import org.jahia.bin.Login;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.modules.saml2.SAML2Util;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.AutoRegisteredBaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.registries.ServicesRegistry;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUser;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.profile.SAML2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;

/**
 * Created by smomin on 5/27/16.
 */
public class AuthenticationValve extends AutoRegisteredBaseAuthValve {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationValve.class);
    private static final String CMS_PREFIX = "/cms";
    private static final String REDIRECT = "redirect";
    private SAML2SettingsService saml2SettingsService;

    /**
     * @param context
     * @param valveContext
     * @throws PipelineException
     */
    @Override
    public void invoke(final Object context,
                       final ValveContext valveContext) throws PipelineException {
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        final HttpServletResponse response = authContext.getResponse();


        final boolean isSAMLLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping()).equals(request.getPathInfo())
                && StringUtils.isNotEmpty(request.getParameter("authenticationService"));

        final boolean isSAMLIncomingLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping() + ".SAML.incoming").equals(request.getPathInfo());

        // check on the domain to make sure the valve is enabled only on the right site and check on site key as it a mandatory value
        final boolean enabled = SAML2Constants.serverName.equals(request.getServerName());
        if (!enabled) {
            valveContext.invokeNext(context);
            return;
        }

        // This is the starting process of the SAML authentication which redirects the user to the IDP login screen
        if (isSAMLLoginProcess) {
            SAML2Util.initialize(() -> {
                // Storing redirect url into cookie to be used when the request is send from IDP to continue the
                // access to the secure resource
                response.addCookie(new Cookie(REDIRECT, request.getParameter(REDIRECT)));
                response.addCookie(new Cookie(SAML2Constants.siteKey, request.getParameter(SAML2Constants.SITE)));

                final SAML2Client client = SAML2Util.getSAML2Client(saml2SettingsService, request);
                final J2EContext webContext = new J2EContext(request, response);
                final HttpAction action = client.redirect(webContext);
                response.getWriter().flush();
                LOGGER.info(action.getMessage());
            });
        } else if (isSAMLIncomingLoginProcess) {
            SAML2Util.initialize(() -> {
                final SAML2Client client = SAML2Util.getSAML2Client(saml2SettingsService, request);
                final J2EContext webContext = new J2EContext(request, response);
                final SAML2Credentials saml2Credentials = client.getCredentials(webContext);
                final SAML2Profile saml2Profile = client.getUserProfile(saml2Credentials, webContext);
                final String uid = saml2Profile.getUsername();
                LOGGER.debug("uid " + uid);
                if (StringUtils.isNotEmpty(uid)) {
                    final JCRUserNode jahiaUserNode = ServicesRegistry.getInstance().getJahiaUserManagerService()
                            .lookupUser(uid, SAML2Util.getCookieValue(request, SAML2Constants.SITE));
                    if (jahiaUserNode != null) {
                        final JahiaUser jahiaUser = jahiaUserNode.getJahiaUser();
                        if (jahiaUser.isAccountLocked()) {
                            LOGGER.info("Login failed. Account is locked for user " + uid);
                            return;
                        }
                        authContext.getSessionFactory().setCurrentUser(jahiaUser);
                    }
                }

                request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.OK);
                response.sendRedirect(SAML2Util.getCookieValue(request, REDIRECT));
            });
        }
        valveContext.invokeNext(context);
    }

    /**
     * @param saml2SettingsService
     */
    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }
}
