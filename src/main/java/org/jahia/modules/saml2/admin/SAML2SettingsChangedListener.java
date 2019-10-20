package org.jahia.modules.saml2.admin;

import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import javax.jcr.RepositoryException;
import javax.jcr.observation.Event;
import javax.jcr.observation.EventIterator;
import org.jahia.services.content.JCRContentUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.context.ApplicationEvent;
import org.springframework.context.ApplicationListener;

public class SAML2SettingsChangedListener implements ApplicationListener<ApplicationEvent> {

    private static final Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsChangedListener.class);
    private SAML2SettingsService saml2SettingsService;

    /**
     * @param event
     */
    @Override
    public void onApplicationEvent(final ApplicationEvent event) {
        if (event instanceof SAML2SettingsChangedEvent) {
            try {
                for (final String siteKey : ((SAML2SettingsChangedEvent) event).getAffectedSites()) {
                    saml2SettingsService.loadSettings(siteKey);
                }
            } catch (RepositoryException e) {
                LOGGER.error("unable to load settings", e);
            }
        }
    }

    /**
     *
     * @param saml2SettingsService
     */
    public void setSaml2SettingsService(final SAML2SettingsService saml2SettingsService) {
        this.saml2SettingsService = saml2SettingsService;
    }

    /**
     *
     */
    public static class SAML2SettingsChangedEvent extends ApplicationEvent {

        private static Logger LOGGER = LoggerFactory.getLogger(SAML2SettingsChangedEvent.class);
        private List<String> affectedSites;

        /**
         *
         * @param events
         */
        public SAML2SettingsChangedEvent(final EventIterator events) {
            super(events);
            affectedSites = new ArrayList<>();
            while (events.hasNext()) {
                final Event event = events.nextEvent();
                try {
                    if (LOGGER.isDebugEnabled()) {
                        LOGGER.debug("event type is {}", event.getType());
                        LOGGER.debug("event path is {}", event.getPath());
                        LOGGER.debug("event user id is {}", event.getUserID());
                    }
                    affectedSites.add(JCRContentUtils.getSiteKey(event.getPath()));
                } catch (RepositoryException e) {
                    LOGGER.warn("error while getting event", e);
                }
            }
        }

        /**
         *
         * @return
         */
        public List<String> getAffectedSites() {
            return Collections.unmodifiableList(affectedSites);
        }
    }
}
