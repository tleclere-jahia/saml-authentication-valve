package org.jahia.modules.saml2.valve.saml;

public class SamlException extends Exception {
    public SamlException(final String message) {
        super(message);
    }

    public SamlException(final String message, Throwable cause) {
        super(message, cause);
    }
}
