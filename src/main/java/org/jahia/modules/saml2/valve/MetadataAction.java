package org.jahia.modules.saml2.valve;

import org.jahia.bin.Action;
import org.jahia.bin.ActionResult;
import org.jahia.modules.saml2.admin.SAML2Settings;
import org.jahia.modules.saml2.admin.SAML2SettingsService;
import org.jahia.services.content.JCRSessionWrapper;
import org.jahia.services.render.RenderContext;
import org.jahia.services.render.Resource;
import org.jahia.services.render.URLResolver;
import org.opensaml.DefaultBootstrap;
import org.opensaml.common.xml.SAMLConstants;
import org.opensaml.saml2.metadata.AssertionConsumerService;
import org.opensaml.saml2.metadata.EntityDescriptor;
import org.opensaml.saml2.metadata.KeyDescriptor;
import org.opensaml.saml2.metadata.NameIDFormat;
import org.opensaml.saml2.metadata.SPSSODescriptor;
import org.opensaml.xml.Configuration;
import org.opensaml.xml.io.Marshaller;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.security.credential.UsageType;
import org.opensaml.xml.security.keyinfo.KeyInfoGenerator;
import org.opensaml.xml.security.x509.BasicX509Credential;
import org.opensaml.xml.security.x509.X509KeyInfoGeneratorFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.w3c.dom.Document;
import sun.security.x509.X509CertImpl;

import javax.servlet.http.HttpServletRequest;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerConfigurationException;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Map;

/**
 * Created by smomin on 5/27/16.
 */
public class MetadataAction extends Action {
    private static final Logger LOGGER = LoggerFactory.getLogger(MetadataAction.class);
    private SAML2SettingsService saml2SettingsService;

    /**
     *
     * @param req
     * @param renderContext
     * @param resource
     * @param session
     * @param parameters
     * @param urlResolver
     * @return
     * @throws Exception
     */
    @Override
    public ActionResult doExecute(final HttpServletRequest req,
                                  final RenderContext renderContext,
                                  final Resource resource,
                                  final JCRSessionWrapper session,
                                  final Map<String, List<String>> parameters,
                                  final URLResolver urlResolver) throws Exception {
        try {
            if (renderContext.getSite() == null) {
                return ActionResult.OK;
            }
            final String siteKey = renderContext.getSite().getSiteKey();
            final SAML2Settings saml2Settings = saml2SettingsService.getSettings(siteKey);
            // initialize the opensaml library
            DefaultBootstrap.bootstrap();

            final EntityDescriptor spEntityDescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(EntityDescriptor.class);
            spEntityDescriptor.setEntityID(saml2Settings.getRelyingPartyIdentifier());
            final SPSSODescriptor spSSODescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(SPSSODescriptor.class);
//            spSSODescriptor.setWantAssertionsSigned(false);
//            spSSODescriptor.setAuthnRequestsSigned(false);

            final X509KeyInfoGeneratorFactory keyInfoGeneratorFactory = new X509KeyInfoGeneratorFactory();
            keyInfoGeneratorFactory.setEmitEntityCertificate(true);
            final KeyInfoGenerator keyInfoGenerator = keyInfoGeneratorFactory.newInstance();


            final KeyDescriptor encKeyDescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(KeyDescriptor.class);
            encKeyDescriptor.setUse(UsageType.ENCRYPTION); //Set usage

            // jtc - signature and credential
            final InputStream encInStream = new FileInputStream(new File(saml2Settings.getEncryptionCertLocation()));
            // position 0 has the key file
            final X509Certificate encCert = new X509CertImpl(encInStream);
            final BasicX509Credential encCredential = new BasicX509Credential();
            encCredential.setEntityCertificate(encCert);

            // Generating key info. The element will contain the public key. The key is used to by the IDP to encrypt data
            encKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(encCredential));
            spSSODescriptor.getKeyDescriptors().add(encKeyDescriptor);


            final KeyDescriptor signKeyDescriptor = SAMLUtil.buildSAMLObjectWithDefaultName(KeyDescriptor.class);
            signKeyDescriptor.setUse(UsageType.SIGNING);  //Set usage

            // Generating key info. The element will contain the public key. The key is used to by the IDP to verify signatures
            final InputStream signInStream = new FileInputStream(new File(saml2Settings.getSigningCertLocation()));
            // position 0 has the key file
            final X509Certificate signCert = new X509CertImpl(signInStream);
            final BasicX509Credential signCredential = new BasicX509Credential();
            signCredential.setEntityCertificate(signCert);

            signKeyDescriptor.setKeyInfo(keyInfoGenerator.generate(signCredential));
            spSSODescriptor.getKeyDescriptors().add(signKeyDescriptor);

            // Request transient pseudonym
            final NameIDFormat nameIDFormat = SAMLUtil.buildSAMLObjectWithDefaultName(NameIDFormat.class);
            nameIDFormat.setFormat("urn:oasis:names:tc:SAML:2.0:nameid-format:transient");
            spSSODescriptor.getNameIDFormats().add(nameIDFormat);

            final AssertionConsumerService assertionConsumerService = SAMLUtil.buildSAMLObjectWithDefaultName(AssertionConsumerService.class);
            assertionConsumerService.setIndex(1);
            assertionConsumerService.setIsDefault(true);
            assertionConsumerService.setBinding(SAMLConstants.SAML2_POST_BINDING_URI);
            // Setting address for our AssertionConsumerService
            assertionConsumerService.setLocation(SAMLUtil.getAssertionConsumerServiceUrl(req));

            spSSODescriptor.getAssertionConsumerServices().add(assertionConsumerService);
            spSSODescriptor.addSupportedProtocol(SAMLConstants.SAML20P_NS);
            spEntityDescriptor.getRoleDescriptors().add(spSSODescriptor);

            final DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
            final DocumentBuilder builder = factory.newDocumentBuilder();
            final Document document = builder.newDocument();
            final Marshaller out = Configuration.getMarshallerFactory().getMarshaller(spEntityDescriptor);
            out.marshall(spEntityDescriptor, document);

            final StreamResult streamResult = new StreamResult(renderContext.getResponse().getWriter());
            final DOMSource source = new DOMSource(document);

            final Transformer transformer = TransformerFactory.newInstance().newTransformer();
            transformer.transform(source, streamResult);
        } catch (ParserConfigurationException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (TransformerConfigurationException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (TransformerException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (IOException e) {
            LOGGER.error(e.getMessage(), e);
        } catch (MarshallingException e) {
            LOGGER.error(e.getMessage(), e);
        }

        return ActionResult.OK;
    }

    public void setSaml2SettingsService(SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }
}
