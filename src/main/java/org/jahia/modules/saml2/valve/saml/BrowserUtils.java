package org.jahia.modules.saml2.valve.saml;

import org.apache.commons.lang.StringEscapeUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.servlet.http.HttpServletResponse;
import java.io.IOException;
import java.io.Writer;
import java.util.Map;

public class BrowserUtils {
    private static final Logger LOGGER = LoggerFactory.getLogger(BrowserUtils.class);

    /**
     * Renders an HTTP response that will cause the browser to POST the specified values to an url.
     *
     * @param url      the url where to perform the POST.
     * @param response the {@link HttpServletResponse}.
     * @param values   the values to include in the POST.
     * @throws IOException thrown if an IO error occurs.
     */
    public static void postUsingBrowser(final String url,
                                        final HttpServletResponse response,
                                        final Map<String, String> values) throws IOException {
        response.setContentType("text/html");
        final Writer writer = response.getWriter();
        writer.write(
                "<html><head></head><body><form id='TheForm' action='"
                        + StringEscapeUtils.escapeHtml(url)
                        + "' method='POST'>");

        for (final String key : values.keySet()) {
            final String encodedKey = StringEscapeUtils.escapeHtml(key);
            final String encodedValue = StringEscapeUtils.escapeHtml(values.get(key));
            writer.write(
                    "<input type='hidden' id='"
                            + encodedKey
                            + "' name='"
                            + encodedKey
                            + "' value='"
                            + encodedValue
                            + "'/>");
            LOGGER.info("<input type='hidden' id='"
                    + encodedKey
                    + "' name='"
                    + encodedKey
                    + "' value='"
                    + encodedValue
                    + "'/>");
        }

        writer.write(
                "</form><script type='text/javascript'>document.getElementById('TheForm').submit();</script></body></html>");
        writer.flush();
    }
}
