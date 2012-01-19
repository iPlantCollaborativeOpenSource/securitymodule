package org.mule.module.iplantsecurity.i18n;

import org.mule.config.i18n.Message;
import org.mule.config.i18n.MessageFactory;

/**
 * Generates error messages that are specific to this module.  The message text is configured in a file called
 * mule-iplantsecurity-messages.properties in src/main/resources/META-INF/services/org/mule/i18n.
 * 
 * @author Dennis Roberts
 */
public class IPlantsecurityMessages extends MessageFactory {
    
    /**
     * The leading part of the bundle file name.
     */
    private static final String BUNDLE_PATH = getBundlePath("iplantsecurity");

    /**
     * The single instance of this class, which is used to obtain the messages.
     */
    private static final IPlantsecurityMessages factory = new IPlantsecurityMessages();

    /**
     * Indicates that user authentication failed.
     * 
     * @return the message.
     */
    public static Message authenticationFailed() {
        return factory.createMessage(BUNDLE_PATH, 1);
    }

    /**
     * Indicates that the user details could not be extracted from the SAML assertion.
     * 
     * @return the message.
     */
    public static Message unableToExtractUserDetails() {
        return factory.createMessage(BUNDLE_PATH, 2);
    }

    /**
     * Indicates that the SAML assertion could not be interpreted.
     * 
     * @return the message.
     */
    public static Message unableToInterpretAssertion() {
        return factory.createMessage(BUNDLE_PATH, 3);
    }
}
