package org.mule.module.iplantsecurity.config;

import java.io.FileInputStream;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.X509Certificate;

import org.apache.xml.security.utils.EncryptionConstants;
import org.iplantc.saml.AssertionBuilder;
import org.iplantc.saml.AssertionEncrypter;
import org.iplantc.saml.Formatter;
import org.mule.DefaultMuleMessage;
import org.mule.api.MuleMessage;
import org.mule.api.security.UnauthorisedException;
import org.mule.module.client.MuleClient;
import org.mule.tck.FunctionalTestCase;
import org.opensaml.xml.signature.SignatureConstants;

import org.apache.xml.security.utils.Base64;

/**
 * Automated functional tests for the security module.
 * 
 * @author Dennis Roberts
 */
public class IPlantsecurityFunctionalTest extends FunctionalTestCase {

    /**
     * The path to the test keystore.
     */
    private static String KEYSTORE_PATH = "src/test/resources/keystore.jceks";

    /**
     * The type of the test keystore.
     */
    private static String KEYSTORE_TYPE = "JCEKS";

    /**
     * The password used to access the test keystore and all of the keys within it.
     */
    private static String KEYSTORE_PASSWORD = "changeit";

    /**
     * Returns the name of the configuration file used in this test.
     */
    @Override
    protected String getConfigResources() {
        return "iplantsecurity-functional-test-config.xml";
    }

    /**
     * Verifies that a user with no authentication information will not be authenticated.
     * 
     * @throws Exception if an error occurs.
     */
    public void testUnauthenticatedUser() throws Exception {
        MuleMessage muleMessage = createMuleMessage("some data", null);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }

    /**
     * Verifies that a user with invalid base64 data in the authentication informaiton will not be authenticated.
     * 
     * @throws Exception if an error occurs.
     */
    public void testInvalidAuthentication() throws Exception {
        MuleMessage muleMessage = createMuleMessage("some data", "I'm authenticated!  Really!");
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }

    /**
     * Verifies that an assertion that is encrypted with an unrecognized encrypting key will not be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testInvalidEncryptingKey() throws Exception {
        String assertion = createAssertion("nobody", "signing", "signing");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }

    /**
     * Verifies that an assertion that is signed with an untrusted signing key will not be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testInvalidSigningKey() throws Exception {
        String assertion = createAssertion("nobody", "encrypting", "encrypting");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }

    /**
     * Verifies that an assertion that does not contain a subject will not be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testMissingSubject() throws Exception {
        String assertion = createAssertion(null, "signing", "encrypting");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }

    /**
     * Verifies that a valid assertion will be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testValidAssertion() throws Exception {
        String assertion = createAssertion("nobody", "signing", "encrypting");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectSuccess("vm://in", muleMessage);
    }

    /**
     * Verifies that we can accept multiple signing keys.
     * 
     * @throws Exception if an error occurs.
     */
    public void testAlternateSigningKey() throws Exception {
        String assertion = createAssertion("nobody", "signing2", "encrypting");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectSuccess("vm://in", muleMessage);
    }

    /**
     * Verifies that an unsigned assertion will not be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testUnsignedAssertion() throws Exception {
        String assertion = createAssertion("nobody", null, "encrypting");
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }
    
    /**
     * Verifies that an unencrypted assertion will not be accepted.
     * 
     * @throws Exception if an error occurs.
     */
    public void testUnencryptedAssertion() throws Exception {
        String assertion = createAssertion("nobody", "signing", null);
        MuleMessage muleMessage = createMuleMessage("some data", assertion);
        expectException("vm://in", muleMessage, UnauthorisedException.class);
    }
    
    /**
     * Performs a test for which we expect the authentication to succeed.
     * 
     * @param addr the address to send the message to.
     * @param muleMessage the message to send.
     * @throws Exception if an error occurs.
     */
    private void expectSuccess(String addr, MuleMessage muleMessage) throws Exception {
        MuleClient client = new MuleClient();
        MuleMessage result = client.send(addr, muleMessage);
        assertNull(result.getExceptionPayload());
        assertNotNull(result.getPayload());
    }

    /**
     * Performs a test for which we expect the authentication to fail.
     * 
     * @param addr the address to send the message to.
     * @param muleMessage the message to send.
     * @param expected the class of the exception we expect to be thrown.
     * @throws Exception if an error occurs.
     */
    @SuppressWarnings("unchecked")
    private void expectException(String addr, MuleMessage muleMessage, Class expected) throws Exception {
        MuleClient client = new MuleClient();
        MuleMessage result = client.send(addr, muleMessage);
        assertNotNull(result.getExceptionPayload());
        assertNotNull(result.getExceptionPayload().getException());
        Throwable e = result.getExceptionPayload().getException();
        if (!(e.getClass().isAssignableFrom(expected))) {
            fail("expected " + expected + "to be thrown, but " + e.getClass() + " was thrown instead");
        }
    }

    /**
     * Creates a Mule message containing the given data and authentication token.
     * 
     * @param data the message payload data.
     * @param authentication the authentication token.
     * @return the Mule message.
     */
    private MuleMessage createMuleMessage(String data, String authentication) {
        MuleMessage muleMessage = new DefaultMuleMessage(data);
        if (authentication != null) {
            muleMessage.setStringProperty("_iplant_auth", authentication);
        }
        return muleMessage;
    }

    /**
     * Creates a SAML assertion.
     * 
     * @param user the username to include in the assertion.
     * @param signingKeyAlias the alias of the key used to sign the assertion.
     * @param encryptingKeyAlias the alias of the key used to encrypt the assertion.
     * @return the assertion as a base64 encoded string.
     * @throws Exception if an error occurs.
     */
    private String createAssertion(String user, String signingKeyAlias, String encryptingKeyAlias) throws Exception {
        AssertionBuilder assertionBuilder = new AssertionBuilder();
        if (user != null) {
            assertionBuilder.setSubject(user);
        }
        if (signingKeyAlias != null) {
            signAssertion(assertionBuilder, signingKeyAlias);
        }
        String retval = encryptingKeyAlias == null
                ? formatAssertion(assertionBuilder)
                : encryptAssertion(assertionBuilder, encryptingKeyAlias);
        return Base64.encode(retval.getBytes());
    }

    /**
     * Signs the assertion being build by the given assertion builder.
     * 
     * @param assertionBuilder the assertion builder.
     * @param signingKeyAlias the alias of the key used to sign the assertion.
     * @throws Exception if an error occurs.
     */
    private void signAssertion(AssertionBuilder assertionBuilder, String signingKeyAlias) throws Exception {
        KeyStore keystore = openKeyStore();
        X509Certificate cert = (X509Certificate) keystore.getCertificate(signingKeyAlias);
        PrivateKey privateKey = (PrivateKey) keystore.getKey(signingKeyAlias, KEYSTORE_PASSWORD.toCharArray());
        String algorithm = SignatureConstants.ALGO_ID_SIGNATURE_RSA_SHA1;
        assertionBuilder.signAssertion(cert, privateKey, algorithm);
    }

    /**
     * Formats an unencrypted assertion.
     * 
     * @param assertionBuilder the builder that is being used to build the assertion.
     * @return the formatted assertion.
     * @throws Exception if an error occurs.
     */
    private String formatAssertion(AssertionBuilder assertionBuilder) throws Exception {
        return new Formatter().format(assertionBuilder.getAssertion());
    }

    /**
     * Encrypts an assertion.
     * 
     * @param assertionBuilder the builder that is being used to build the assertion.
     * @param encryptingKeyAlias the alias of the key used to encrypt the assertion.
     * @return the encrypted assertion.
     * @throws Exception if an error occurs.
     */
    private String encryptAssertion(AssertionBuilder assertionBuilder, String encryptingKeyAlias) throws Exception {
        KeyStore keystore = openKeyStore();
        PublicKey publicKey = keystore.getCertificate(encryptingKeyAlias).getPublicKey();
        AssertionEncrypter encrypter = new AssertionEncrypter();
        encrypter.setPublicKey(publicKey);
        encrypter.setPublicKeyAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSAOAEP);
        encrypter.setSecretKeyAlgorithm(EncryptionConstants.ALGO_ID_BLOCKCIPHER_AES256);
        return encrypter.encryptAssertion(assertionBuilder.getAssertion());
    }

    /**
     * Opens the test keystore.
     * 
     * @return the keystore.
     * @throws Exception if an error occurs.
     */
    private KeyStore openKeyStore() throws Exception {
        FileInputStream in = null;
        try {
            KeyStore keystore = KeyStore.getInstance(KEYSTORE_TYPE);
            in = new FileInputStream(KEYSTORE_PATH);
            keystore.load(in, KEYSTORE_PASSWORD.toCharArray());
            return keystore;
        }
        finally {
            if (in != null) {
                in.close();
            }
        }
    }
}
