package org.jahia.modules.saml2.valve;

import org.apache.commons.collections.CollectionUtils;
import org.apache.commons.lang.StringUtils;
import org.jahia.bin.Login;
import org.jahia.modules.saml2.admin.SAML2Settings;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.modules.saml2.valve.saml.SamlClient;
import org.jahia.modules.saml2.valve.saml.SamlException;
import org.jahia.modules.saml2.valve.saml.SamlResponse;
import org.jahia.params.valves.AuthValveContext;
import org.jahia.params.valves.AutoRegisteredBaseAuthValve;
import org.jahia.params.valves.LoginEngineAuthValveImpl;
import org.jahia.pipelines.PipelineException;
import org.jahia.pipelines.valves.ValveContext;
import org.jahia.registries.ServicesRegistry;
import org.jahia.services.content.decorator.JCRUserNode;
import org.jahia.services.usermanager.JahiaUser;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Attribute;
import org.opensaml.saml2.core.AttributeStatement;
import org.opensaml.xml.XMLObject;
import org.opensaml.xml.schema.impl.XSAnyImpl;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import sun.security.x509.X509CertImpl;

import javax.servlet.http.Cookie;
import javax.servlet.http.HttpServletRequest;
import javax.servlet.http.HttpServletResponse;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.io.InputStreamReader;
import java.io.Reader;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import static org.jahia.modules.saml2.SAML2Constants.SAML_INCOMING;

/**
 * Created by smomin on 5/27/16.
 */
public class AuthenticationValve extends AutoRegisteredBaseAuthValve {
    private static final Logger LOGGER = LoggerFactory.getLogger(AuthenticationValve.class);
    private static final String CMS_PREFIX = "/cms";
    private static final String REDIRECT = "redirect";
    private static final String SITE = "site";
    private static final String UID = "uid";
    private SAML2SettingsService saml2SettingsService;

    /**
     *
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
                && (Login.getMapping() + SAML_INCOMING).equals(request.getPathInfo());

        // This is the starting process of the SAML authentication which redirects the user to the IDP login screen
        if (isSAMLLoginProcess) {
            try {
                // Storing redirect url into cookie to be used when the request is send from IDP to continue the
                // access to the secure resource
                response.addCookie(new Cookie(REDIRECT, request.getParameter(REDIRECT)));
                response.addCookie(new Cookie(SITE, request.getParameter(SITE)));
                final SAML2Settings saml2Settings = saml2SettingsService.getSettings(getCookieValue(request, SITE));
                if (saml2Settings.getEnabled()) {
                    final InputStream inStream = new FileInputStream(new File(saml2Settings.getIdpMetaDataLocation()));
                    final Reader reader = new InputStreamReader(inStream);
                    final SamlClient client = SamlClient.fromMetadata(saml2Settings.getRelyingPartyIdentifier(),
                            SAMLUtil.getAssertionConsumerServiceUrl(request),
                            reader);
                    client.redirectToIdentityProvider(response, null);
                }
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            } catch (SamlException e) {
                LOGGER.error(e.getMessage(), e);
            }
        } else if (isSAMLIncomingLoginProcess) {
            // This is the login complete process on a successful login from IDP to continue the user to access the
            // secure part of the site.
            try {
                final SAML2Settings saml2Settings = saml2SettingsService.getSettings(getCookieValue(request, SITE));
                final InputStream inStream = new FileInputStream(new File(saml2Settings.getIdpMetaDataLocation()));
                final Reader reader = new InputStreamReader(inStream);

                // Generating key info. The element will contain the public key. The key is used to by the IDP
                // to verify signatures
                final InputStream signInStream = new FileInputStream(
                        new File(saml2Settings.getSigningCertLocation()));
                // position 0 has the key file
                final X509Certificate signCert = new X509CertImpl(signInStream);
                final SamlClient client = SamlClient.fromMetadata(reader,
                        saml2Settings.getIdentityProviderUrl(),
                        signCert);

                // To process the POST containing the SAML response
                final SamlResponse samlResponse = client.processPostFromIdentityProvider(request);
                final Assertion assertion = samlResponse.getAssertion();

                // TODO: Name id is encrypted so need to figure out how to configure IDP not to encrypt this value
                // TODO: so I can use it instead of looking up the uid in the attribute statements.
                final List<AttributeStatement> attributeStatements = assertion.getAttributeStatements();
                final Map<String, String> properties = new HashMap<String, String>(5);
                if (CollectionUtils.isNotEmpty(attributeStatements)) {
                    for (final AttributeStatement attributeStatement : attributeStatements) {
                        final List<Attribute> attributes = attributeStatement.getAttributes();
                        if (CollectionUtils.isNotEmpty(attributes)) {
                            for (final Attribute attribute : attributes) {
                                final String name = attribute.getFriendlyName();
                                LOGGER.debug("name", name);
                                final List<XMLObject> attributeValues = attribute.getAttributeValues();
                                if (CollectionUtils.isNotEmpty(attributeValues)) {
                                    for (final XMLObject attributeValue : attributeValues) {
                                        final String value = ((XSAnyImpl) attributeValue).getTextContent();
                                        LOGGER.debug("attributeValue", value);
                                        properties.put(name, value);
                                    }
                                }
                            }
                        }
                    }
                }
                final String uid = properties.get(UID);
                LOGGER.debug("uid " + uid);
                if (StringUtils.isNotEmpty(uid)) {
                    final JCRUserNode jahiaUserNode = ServicesRegistry.getInstance().getJahiaUserManagerService()
                            .lookupUser(uid, getCookieValue(request, SITE));
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
                response.sendRedirect(getCookieValue(request, REDIRECT));
            } catch (CertificateException e) {
                LOGGER.error(e.getMessage(), e);
            } catch (SamlException e) {
                LOGGER.error(e.getMessage(), e);
            } catch (FileNotFoundException e) {
                LOGGER.error(e.getMessage(), e);
            } catch (IOException e) {
                LOGGER.error(e.getMessage(), e);
            }
        }
        valveContext.invokeNext(context);
    }

    /**
     * @param request
     */
    private String getCookieValue(final HttpServletRequest request,
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
     *
     * @param saml2SettingsService
     */
    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }
}
