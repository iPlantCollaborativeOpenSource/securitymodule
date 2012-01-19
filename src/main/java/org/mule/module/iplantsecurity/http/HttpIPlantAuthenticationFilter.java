package org.mule.module.iplantsecurity.http;

import net.sf.json.JSONObject;
import org.iplantc.saml.Saml2Exception;
import org.iplantc.security.Saml2AssertionEncoding;
import org.iplantc.security.Saml2AuthenticationToken;
import org.iplantc.security.Saml2UserDetails;
import org.iplantc.security.SecurityConstants;
import org.mule.api.MuleEvent;
import org.mule.api.lifecycle.InitialisationException;
import org.mule.api.security.Authentication;
import org.mule.api.security.CryptoFailureException;
import org.mule.api.security.EncryptionStrategyNotFoundException;
import org.mule.api.security.SecurityContext;
import org.mule.api.security.SecurityException;
import org.mule.api.security.SecurityProviderNotFoundException;
import org.mule.api.security.UnauthorisedException;
import org.mule.api.security.UnknownAuthenticationTypeException;
import org.mule.config.i18n.Message;
import org.mule.module.iplantsecurity.i18n.IPlantsecurityMessages;
import org.mule.module.spring.security.SpringAuthenticationAdapter;
import org.mule.security.AbstractEndpointSecurityFilter;
import org.mule.transport.http.HttpConnector;
import org.mule.transport.http.HttpConstants;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.xml.io.MarshallingException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.springframework.security.AuthenticationException;
import org.springframework.util.Assert;

/**
 * An HTTP transport filter that authenticates messages based on SAML 2.0 assertions in a custom HTTP header.
 *
 * @author Dennis Roberts
 */
public class HttpIPlantAuthenticationFilter extends AbstractEndpointSecurityFilter {

    /**
     * A logger for error and informational messages.
     */
    private final Logger logger = LoggerFactory.getLogger(HttpIPlantAuthenticationFilter.class);

    private boolean securityEnabled = true;

    /**
     * Used to decode the assertions.
     */
    private Saml2AssertionEncoding decoder;

    /**
     * The default constructor.
     */
    public HttpIPlantAuthenticationFilter() {
        super();
    }

    /**
     * Set security to enabled or disabled.
     * @param securityEnabled
     */
    public void setSecurityEnabled(boolean securityEnabled) {
    	this.securityEnabled = securityEnabled;
    }

    /**
     * The setter for the decoder property.
     *
     * @param decoder the new decoder.
     */
    public void setDecoder(Saml2AssertionEncoding decoder) {
        Assert.notNull(decoder, "the assertion decoder may not be null");
        this.decoder = decoder;
    }

    /**
     * The getter for the decoder property.
     *
     * @param decoder the assertion decoder.
     */
    public Saml2AssertionEncoding getDecoder() {
        return decoder;
    }

    /**
     * {@inheritDoc}
     */
    @Override
    protected void authenticateInbound(MuleEvent event) throws SecurityException, CryptoFailureException,
            SecurityProviderNotFoundException, EncryptionStrategyNotFoundException, UnknownAuthenticationTypeException
    {
    	if (securityEnabled) {
	        try {
	            String encodedAssertion = event.getMessage().getStringProperty(SecurityConstants.ASSERTION_HEADER, null);
	            Assertion assertion = decodeAssertion(encodedAssertion);
	            Authentication authnRequest = createAuthenticationRequest(assertion, encodedAssertion);
	            Authentication authnResult = attemptAuthentication(authnRequest);
	            recordSuccessfulAuthentication(event, authnResult);
	        }
	        catch (SecurityException e) {
	            event.getMessage().setIntProperty(HttpConnector.HTTP_STATUS_PROPERTY, HttpConstants.SC_UNAUTHORIZED);
	            event.getMessage().setPayload(formatAuthenticationFailedResponse());
	            throw e;
	        }
    	}
    }

    /**
     * Formats the response body when authentication failed for any reason.  We don't currently provide any details
     * about why the authentication failed.
     * 
     * @return the response body.
     */
    private String formatAuthenticationFailedResponse() {
        JSONObject json = new JSONObject();
        json.put("name", "org.mule.api.security.SecurityException");
        json.put("message", "Authentication failed");
        return json.toString();
    }

    /**
     * Records a successful authentication attempt.
     *
     * @param event the event for which the authentication is being performed.
     * @param authnResult the result of the authentication.
     * @throws UnknownAuthenticationTypeException if the security context can't be created.
     */
    private void recordSuccessfulAuthentication(MuleEvent event, Authentication authnResult)
            throws UnknownAuthenticationTypeException
    {
        logger.debug("authentication success: {}", authnResult);
        SecurityContext context = getSecurityManager().createSecurityContext(authnResult);
        context.setAuthentication(authnResult);
        event.getSession().setSecurityContext(context);
    }

    /**
     * Attempts to authenticate the user.
     *
     * @param authnRequest the authentication request.
     * @return the authentication result.
     * @throws SecurityException if the authentication fails.
     * @throws SecurityProviderNotFoundException if the configured security provider doesn't exist.
     */
    private Authentication attemptAuthentication(Authentication authnRequest) throws SecurityException,
            SecurityProviderNotFoundException
    {
        try {
            return getSecurityManager().authenticate(authnRequest);
        }
        catch (AuthenticationException e) {
            Message msg = IPlantsecurityMessages.authenticationFailed();
            logger.debug(msg.toString(), e);
            throw new UnauthorisedException(msg, e);
        }
    }

    /**
     * Creates the authentication request from the given SAML assertion.
     *
     * @param assertion the assertion to get the user details from.
     * @param encodedAssertion the assertion before it was processed.
     * @return the new authentication request.
     * @throws SecurityException if the user details can't be extracted from the assertion.
     */
    private Authentication createAuthenticationRequest(Assertion assertion, String encodedAssertion)
            throws SecurityException
    {
        try {
            Saml2AuthenticationToken springAuthnRequest = new Saml2AuthenticationToken(assertion, encodedAssertion);
            Saml2UserDetails userDetails = (Saml2UserDetails) springAuthnRequest.getPrincipal();
            return new SpringAuthenticationAdapter(springAuthnRequest, userDetails.getAttributes());
        }
        catch (MarshallingException e) {
            Message msg = IPlantsecurityMessages.unableToExtractUserDetails();
            logger.debug(msg.toString(), e);
            throw new UnauthorisedException(msg, e);
        }
    }

    /**
     * Decodes the given encoded SAML assertion.
     *
     * @param encodedAssertion the assertion to encode.
     * @return the decoded assertion.
     * @throws SecurityException if the assertion can't be decoded.
     */
    private Assertion decodeAssertion(String encodedAssertion) throws SecurityException {
        try {
            return decoder.decodeAssertion(encodedAssertion);
        }
        catch (Saml2Exception e) {
            Message msg = IPlantsecurityMessages.unableToInterpretAssertion();
            logger.debug(msg.toString(), e);
            throw new UnauthorisedException(msg, e);
        }
    }

    /**
     * Authenticates an outgoing message.
     *
     * @param event the Mule event containing the message.
     * @throws SecurityException if the authentication fails.
     * @throws SecurityProviderNotFoundException if the configured security provider can't be found.
     * @throws CryptoFailureException if the authentication fails because of a cryptography error.
     */
    @Override
    protected void authenticateOutbound(MuleEvent event) throws SecurityException, SecurityProviderNotFoundException,
            CryptoFailureException
    {
        SecurityContext securityContext = event.getSession().getSecurityContext();
        if (securityContext == null) {
            handleMissingSecurityContext(event);
        }
        else {
            completeOutboundAuthentication(event);
        }
    }

    /**
     * Handles the case where the security context is missing.
     *
     * @param event the Mule event.
     * @throws UnauthorisedException if we're supposed to authenticate.
     */
    private void handleMissingSecurityContext(MuleEvent event) throws UnauthorisedException {
        if (isAuthenticate()) {
            throw new UnauthorisedException(event.getMessage(), null, event.getEndpoint(), this);
        }
    }

    /**
     * Completes the outbound authentication.
     *
     * @param event the Mule event.
     * @throws SecurityException if the authentication can't be completed.
     * @throws SecurityProviderNotFoundException if the configured security provider doesn't exist.
     */
    private void completeOutboundAuthentication(MuleEvent event) throws SecurityException,
            SecurityProviderNotFoundException
    {
        Authentication authn = event.getSession().getSecurityContext().getAuthentication();
        if (isAuthenticate()) {
            authn = getSecurityManager().authenticate(authn);
            logger.debug("authentication success: {}", authn);
        }
        String credentials = (String) authn.getCredentials();
        event.getMessage().setStringProperty(SecurityConstants.ASSERTION_HEADER, credentials);
    }

    /**
     * Verifies that the initialization is complete.
     *
     * @throws InitialisationException if the initialization isn't complete.
     */
    @Override
    protected void doInitialise() throws InitialisationException {
        Assert.notNull(decoder, "an assertion decoder is required");
    }
}
