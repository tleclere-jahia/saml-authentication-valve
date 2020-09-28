package org.jahia.modules.saml2;

import org.jahia.modules.jahiaauth.service.ConnectorConfig;
import org.jahia.modules.jahiaauth.service.ConnectorPropertyInfo;
import org.jahia.modules.jahiaauth.service.ConnectorService;
import org.pac4j.core.profile.definition.CommonProfileDefinition;
import org.pac4j.saml.profile.SAML2Profile;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

public class SamlConnector implements ConnectorService {

    private SAML2Util util;

    @Override
    public String getServiceName() {
        return "Saml";
    }

    @Override
    public String getProtectedResourceUrl() {
        return null;
    }

    @Override
    public List<ConnectorPropertyInfo> getAvailableProperties() {
        List<ConnectorPropertyInfo> array = new ArrayList<>();
        array.add(new ConnectorPropertyInfo("username", "string"));
        new CommonProfileDefinition<SAML2Profile>().getPrimaryAttributes().forEach(s -> array.add(new ConnectorPropertyInfo(s, s.equals(CommonProfileDefinition.EMAIL) ? "email" : "string")));
        return array;
    }

    public void validateSettings(ConnectorConfig settings) throws IOException {
        util.validateSettings(settings);
    }

    public void setUtil(SAML2Util util) {
        this.util = util;
    }
}
