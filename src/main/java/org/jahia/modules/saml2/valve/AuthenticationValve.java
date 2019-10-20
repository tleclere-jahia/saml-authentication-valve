package org.jahia.modules.saml2.valve;

import java.util.ArrayList;
import java.util.Locale;
import java.util.Objects;
import java.util.Properties;
import javax.jcr.RepositoryException;
import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import org.apache.commons.lang.StringUtils;
import org.jahia.api.Constants;
import org.jahia.bin.Login;
import org.jahia.modules.saml2.SAML2Constants;
import org.jahia.modules.saml2.SAML2Util;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.modules.saml2.utils.JCRConstants;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.AutoRegisteredBaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.services.content.JCRNodeWrapper;
import org.jahia.services.content.JCRSessionFactory;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUser;
import org.jahia.services.usermanager.JahiaUserManagerService;
import org.pac4j.core.context.J2EContext;
import org.pac4j.core.exception.HttpAction;
import org.pac4j.saml.client.SAML2Client;
import org.pac4j.saml.credentials.SAML2Credentials;
import org.pac4j.saml.profile.SAML2Profile;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class AuthenticationValve extends AutoRegisteredBaseAuthValve {

    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationValve.class);
    private static final String CMS_PREFIX = "/cms";
    private static final String DEFAULT_LOCALE = "en_US";
    private static final String REDIRECT = "redirect";
    private SAML2SettingsService saml2SettingsService;
    private JCRSessionWrapper sessionWrapper;
    private JahiaUserManagerService jahiaUserManagerService;

    @Override
    public void invoke(final Object context,
            final ValveContext valveContext) throws PipelineException {
        final AuthValveContext authContext = (AuthValveContext) context;
        final HttpServletRequest request = authContext.getRequest();
        final HttpServletResponse response = authContext.getResponse();

        final boolean isSAMLLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping()).equals(request.getPathInfo());

        final boolean isSAMLIncomingLoginProcess = CMS_PREFIX.equals(request.getServletPath())
                && (Login.getMapping() + ".SAML.incoming").equals(request.getPathInfo());

        // check on the domain to make sure the valve is enabled only on the right site and check on site key as it a mandatory value
        // TODO: check if the module is activated for the current website
        final boolean enabled = true;

        if (!enabled) {
            valveContext.invokeNext(context);
            return;
        }

        // This is the starting process of the SAML authentication which redirects the user to the IDP login screen
        if (isSAMLLoginProcess) {
            // TODO: retrieve siteKey from the request
            final String siteKey = "";
            SAML2Util.initialize(() -> {
                // Storing redirect url into cookie to be used when the request is send from IDP to continue the
                // access to the secure resource
                response.addCookie(new Cookie(REDIRECT, request.getParameter(REDIRECT).replaceAll("\n\r", "")));
                response.addCookie(new Cookie(siteKey, request.getParameter(SAML2Constants.SITE).replaceAll("\n\r", "")));

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
                final String email = saml2Profile.getEmail();
                LOGGER.debug("email of SAML Profile: " + email);

                JCRUserNode jahiaUserNode = null;

                if (StringUtils.isNotEmpty(email)) {
                    // TODO: split this processing of the user at the back-end level in the same way than the OAuth modules
                    jahiaUserNode = this.processSSOUserInJcr(email, saml2Profile, request);
                    final JahiaUser jahiaUser = jahiaUserNode.getJahiaUser();
                    if (jahiaUser.isAccountLocked()) {
                        LOGGER.info("Login failed. Account is locked for user " + email);
                    }
                    authContext.getSessionFactory().setCurrentUser(jahiaUser);
                    request.getSession().setAttribute(Constants.SESSION_USER, jahiaUser);
                }

                request.setAttribute(LoginEngineAuthValveImpl.VALVE_RESULT, LoginEngineAuthValveImpl.OK);

                // Get the redirection URL from the cookie, if not set takes the value is taken from the site settings
                String redirection = retrieveRedirectUrl(request);
                response.sendRedirect(redirection);
            });
        }
        valveContext.invokeNext(context);
    }

    /**
     * Update user is exist or create a new user for site with sso profile properties.
     *
     * @param email
     * @param saml2Profile
     * @param request
     * @return
     * @throws RepositoryException
     */
    private JCRUserNode processSSOUserInJcr(String email, SAML2Profile saml2Profile, HttpServletRequest request) throws RepositoryException {
        this.sessionWrapper = JCRSessionFactory.getInstance()
                .getCurrentSystemSession(
                        null,
                        (request.getLocale() != null) ? request.getLocale() : new Locale(DEFAULT_LOCALE),
                        new Locale(DEFAULT_LOCALE));
        JCRUserNode ssoUserNode = null;
        // TODO: retrieve siteKey from the request
        final String siteKey = "";
        if (this.jahiaUserManagerService.userExists(email, siteKey)) {
            ssoUserNode = this.jahiaUserManagerService.lookupUser(email, siteKey, this.sessionWrapper);
            JCRNodeWrapper jcrNodeWrapper = ssoUserNode.getDecoratedNode();
            boolean isUpdated = this.updateProperties(jcrNodeWrapper, saml2Profile);
            //saving session if any property is updated for user.
            if (isUpdated) {
                this.sessionWrapper.save();
            }
        } else {
            // TODO: generate random password
            ssoUserNode = jahiaUserManagerService.createUser(email, siteKey,
                    "SAH-1*", this.initialProperties(saml2Profile), this.sessionWrapper);
            this.sessionWrapper.save();
        }
        return ssoUserNode;
    }

    /**
     * properties for new user.
     */
    private Properties initialProperties(SAML2Profile saml2Profile) {
        Properties properties = new Properties();
        properties.setProperty(JCRConstants.USER_PROPERTY_EMAIL, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_EMAIL, saml2Profile));
        properties.setProperty(JCRConstants.USER_PROPERTY_LASTNAME, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_LASTNAME, saml2Profile));
        properties.setProperty(JCRConstants.USER_PROPERTY_FIRSTNAME, this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_FIRSTNAME, saml2Profile));
        return properties;
    }

    /**
     * Update properties for existing user node.
     *
     * @param jcrNodeWrapper
     * @param saml2Profile
     * @throws RepositoryException
     */
    private boolean updateProperties(JCRNodeWrapper jcrNodeWrapper, SAML2Profile saml2Profile) throws RepositoryException {
        boolean isUpdated = false;
        String email = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_EMAIL, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_EMAIL))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_EMAIL).equals(email)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_EMAIL, email);
            isUpdated = true;
        }

        String lastname = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_LASTNAME, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_LASTNAME))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_LASTNAME).equals(lastname)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_LASTNAME, lastname);
            isUpdated = true;
        }

        String firstname = this.getProfileAttribute(SAML2Constants.SAML2_USER_PROPERTY_FIRSTNAME, saml2Profile);
        if (Objects.isNull(jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_FIRSTNAME))
                || !jcrNodeWrapper.getPropertyAsString(JCRConstants.USER_PROPERTY_FIRSTNAME).equals(firstname)) {
            jcrNodeWrapper.setProperty(JCRConstants.USER_PROPERTY_FIRSTNAME, firstname);
            isUpdated = true;
        }

        return isUpdated;
    }

    /**
     * Fetch user profile attributes from SAML profile.
     *
     * @param name
     * @param saml2Profile
     * @return
     */
    private String getProfileAttribute(String name, SAML2Profile saml2Profile) {
        ArrayList<String> strings = saml2Profile.getAttribute(name, ArrayList.class);
        if (Objects.nonNull(strings)) {
            return strings.get(0);
        }
        return "";
    }

    /**
     * Gets the redirection URL from the cookie, if not set takes the value is taken from the site settings
     *
     * @param request : the http request
     * @return the redirection URL
     */
    private String retrieveRedirectUrl(HttpServletRequest request) {
        String redirection = SAML2Util.getCookieValue(request, REDIRECT);
        if (StringUtils.isEmpty(redirection)) {
            // TODO: retrieve siteKey from the request
            final String siteKey = "";
            redirection = this.saml2SettingsService.getSettings(siteKey).getPostLoginPath();
            if (StringUtils.isEmpty(redirection)) {
                // default value
                redirection = "/";
            }
        }

        return redirection;
    }

    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }

    public void setJahiaUserManagerService(JahiaUserManagerService jahiaUserManagerService) {
        this.jahiaUserManagerService = jahiaUserManagerService;
    }
}
