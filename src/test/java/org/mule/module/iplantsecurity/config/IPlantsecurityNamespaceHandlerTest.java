package org.mule.module.iplantsecurity.config;

import java.util.Arrays;
import java.util.Collection;

import org.iplantc.security.Saml2AssertionEncoding;
import org.mule.module.iplantsecurity.http.HttpIPlantAuthenticationFilter;
import org.mule.tck.FunctionalTestCase;

/**
 * Test case for the iPlant security namespace handler.
 * 
 * @author Dennis Roberts
 */
public class IPlantsecurityNamespaceHandlerTest extends FunctionalTestCase {

    /**
     * Returns the name of the test configuration file.
     */
    @Override
    protected String getConfigResources() {
        return "iplantsecurity-namespace-config.xml";
    }

    /**
     * Verifies that the namespace handler correctly loads a configuration file.
     * 
     * @throws Exception if an error occurs.
     */
    @SuppressWarnings("unchecked")
    public void testConfig() throws Exception {
        Collection collection = muleContext.getRegistry().lookupObjects(HttpIPlantAuthenticationFilter.class);
        assertEquals(1, collection.size());
        HttpIPlantAuthenticationFilter filter = (HttpIPlantAuthenticationFilter) collection.toArray()[0];
        Saml2AssertionEncoding decoder = filter.getDecoder();
        validateDecoder(decoder);
    }

    /**
     * Verifies that the decoder was initialized correctly.
     * 
     * @param decoder the decoder to verify.
     * @throws Exception if an error occurs.
     */
    private void validateDecoder(Saml2AssertionEncoding decoder) throws Exception {
        assertNotNull(decoder);
        assertEquals("keystore.jceks", decoder.getKeyStorePath());
        assertEquals("changeit", decoder.getKeyStorePassword());
        assertEquals("JCEKS", decoder.getKeyStoreType());
        assertEquals("encrypting", decoder.getKeyEncryptingKeyPairAlias());
        assertEquals("changeit", decoder.getKeyEncryptingKeyPairPassword());
        assertEquals(Arrays.asList("signing", "signing2"), decoder.getTrustedSigningCertificateAliases());
    }
}
