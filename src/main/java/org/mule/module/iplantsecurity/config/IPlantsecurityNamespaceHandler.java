package org.mule.module.iplantsecurity.config;

import org.iplantc.security.Saml2AssertionEncoding;
import org.mule.config.spring.parsers.collection.ChildListDefinitionParser;
import org.mule.config.spring.parsers.generic.ChildDefinitionParser;
import org.mule.config.spring.parsers.generic.DescendentDefinitionParser;
import org.mule.config.spring.parsers.generic.TextDefinitionParser;
import org.mule.module.iplantsecurity.http.HttpIPlantAuthenticationFilter;
import org.springframework.beans.factory.xml.BeanDefinitionParser;
import org.springframework.beans.factory.xml.NamespaceHandlerSupport;

/**
 * Registers a Bean Definition Parser for handling elements defined in META-INF/mule-mulemoduleiplantsecurity.xsd
 */
public class IPlantsecurityNamespaceHandler extends NamespaceHandlerSupport {

    /**
     * Initializes the definition parsers for our custom beans.
     */
    public void init() {
        registerBeanDefinitionParser("iplant-security-filter", getIPlantSecurityFilterParser());
        registerTextDefinitionParser("securityEnabled", "securityEnabled");
        registerBeanDefinitionParser("decoder", getAssertionEncodingTypeParser());
        registerTextDefinitionParser("key-store-path", "keyStorePath");
        registerTextDefinitionParser("key-store-password", "keyStorePassword");
        registerTextDefinitionParser("key-store-type", "keyStoreType");
        registerTextDefinitionParser("key-encrypting-key-pair-alias", "keyEncryptingKeyPairAlias");
        registerTextDefinitionParser("key-encrypting-key-pair-password", "keyEncryptingKeyPairPassword");
        registerBeanDefinitionParser("trusted-signing-certificate-aliases", getTrustedSigningCertificatesParser());
    }

    /**
     * Obtains the bean definition parser for the decoder property of IPlantsecurityFilter.
     *
     * @return the new bean definition parser.
     */
    private BeanDefinitionParser getAssertionEncodingTypeParser() {
        return new ChildDefinitionParser("decoder", Saml2AssertionEncoding.class);
    }

    /**
     * Obtains the bean definition parser for the iPlant security filter bean.
     *
     * @return the new bean definition parser.
     */
    private BeanDefinitionParser getIPlantSecurityFilterParser() {
        return new DescendentDefinitionParser("securityFilter", HttpIPlantAuthenticationFilter.class);
    }

    /**
     * Registers a text definition parser, which can be used to define the values of simple named properties.
     *
     * @param elementName the name of the XML element.
     * @param setterName the name of the property setter.
     */
    private void registerTextDefinitionParser(String elementName, String setterName) {
        registerBeanDefinitionParser(elementName, new TextDefinitionParser(setterName));
    }

    /**
     * Obtains the bean definition parser for the trustedSigningCertificateAliases property of Saml2EncryptionEncoding.
     *
     * @return the new bean definition parser.
     */
    private BeanDefinitionParser getTrustedSigningCertificatesParser() {
        return new ChildListDefinitionParser("trustedSigningCertificateAliases");
    }
}
