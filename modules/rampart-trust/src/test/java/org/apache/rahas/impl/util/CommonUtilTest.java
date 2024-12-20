/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.apache.rahas.impl.util;

import junit.framework.Assert;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.rahas.RahasData;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.rahas.impl.TokenIssuerUtil;
import org.apache.rahas.test.util.AbstractTestCase;
import org.apache.rahas.test.util.TestCallbackHandler;
import org.apache.rahas.test.util.TestSAMLCallbackHandler;
import org.apache.rahas.test.util.TestUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.common.WSEncryptionPart;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.dom.message.WSSecEncrypt;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xmlsec.signature.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import javax.crypto.SecretKey;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import java.util.*;

/**
 * A test class for common util.
 */
public class CommonUtilTest extends AbstractTestCase {

    private boolean isConfigFromFile = false;

    private String configurationElement = "<configuration><saml-issuer-config>" +
            "<issuerName>Test_STS</issuerName>" +
            "<issuerKeyAlias>ip</issuerKeyAlias>" +
            "<issuerKeyPassword>password</issuerKeyPassword>" +
            "<cryptoProperties><crypto provider=\"org.apache.ws.security.components.crypto.Merlin\">" +
            "<property name=\"org.apache.ws.security.crypto.merlin.keystore.type\">pkcs12</property>" +
            "<property name=\"org.apache.ws.security.crypto.merlin.file\">src/test/resources/apache.pkcs12</property>" +
            "<property name=\"org.apache.ws.security.crypto.merlin.keystore.password\">password</property></crypto>" +
            "</cryptoProperties>" +
            "<timeToLive>300000</timeToLive>" +
            "<keySize>256</keySize>" +
            "<addRequestedAttachedRef /><addRequestedUnattachedRef />" +
            "<keyComputation>2</keyComputation>" +
            "<proofKeyType>BinarySecret</proofKeyType>" +
            "<trusted-services>" +
            "<service alias=\"bob\">http://localhost:8080/axis2/services/STS</service>" +
            "</trusted-services></saml-issuer-config></configuration>";

    private String configurationFileName = "sts-aar-resources/saml-issuer-config.xml";

    private void checkConfigurations(SAMLTokenIssuerConfig tokenIssuerConfig) throws TrustException {

        Assert.assertEquals("Test_STS", tokenIssuerConfig.getIssuerName());
        Assert.assertEquals("ip", tokenIssuerConfig.getIssuerKeyAlias());
        Assert.assertEquals("password", tokenIssuerConfig.getIssuerKeyPassword());
        Assert.assertEquals(300000, tokenIssuerConfig.getTtl());
        Assert.assertEquals(256, tokenIssuerConfig.getKeySize());
        Assert.assertEquals(true, tokenIssuerConfig.isAddRequestedAttachedRef());
        Assert.assertEquals(true, tokenIssuerConfig.isAddRequestedUnattachedRef());
        Assert.assertEquals(2, tokenIssuerConfig.getKeyComputation());
        Assert.assertEquals("BinarySecret", tokenIssuerConfig.getProofKeyType());

        Map trustedServices = tokenIssuerConfig.getTrustedServices();
        Set trustedServiceSet = trustedServices.entrySet();
        for (Object aTrustedServiceSet : trustedServiceSet) {
            Map.Entry pairs = (Map.Entry) aTrustedServiceSet;
            Assert.assertEquals("http://localhost:8080/axis2/services/STS", (String)pairs.getKey());
            Assert.assertEquals("bob", (String) pairs.getValue());
        }

        OMElement cryptoPropertiesElement = tokenIssuerConfig.getCryptoPropertiesElement();
        Assert.assertNotNull(cryptoPropertiesElement);

        OMElement crypto = cryptoPropertiesElement.getFirstChildWithName(SAMLTokenIssuerConfig.CRYPTO);
        Assert.assertNotNull(crypto);

        Iterator children = crypto.getChildElements();
        while (children.hasNext()) {
            OMElement child = (OMElement)children.next();
            OMAttribute attribute = child.getAttribute(new QName("name"));

            if (attribute.getAttributeValue().equals("org.apache.ws.security.crypto.merlin.keystore.type")) {
                Assert.assertEquals(child.getText(), "pkcs12");
                continue;
            }

            if (attribute.getAttributeValue().equals("org.apache.ws.security.crypto.merlin.file")) {

                if (!this.isConfigFromFile) {
                    Assert.assertEquals(child.getText(), "src/test/resources/apache.pkcs12");
                } else {
                    Assert.assertEquals(child.getText(), "META-INF/rahas-sts2024.pkcs12");
                }
                continue;
            }

            if (attribute.getAttributeValue().equals("org.apache.ws.security.crypto.merlin.keystore.password")) {
                Assert.assertEquals(child.getText(), "password");
                continue;
            }

            Assert.fail("Unexpected values returned - " + attribute.getAttributeValue());
        }

    }

    public void testTokenIssuerConfigurationsUsingOMElement() throws XMLStreamException, TrustException {

        this.isConfigFromFile = false;
        OMElement element = AXIOMUtil.stringToOM(this.configurationElement);
        SAMLTokenIssuerConfig tokenIssuerConfig = CommonUtil.createTokenIssuerConfiguration(element);
        Assert.assertNotNull(tokenIssuerConfig);
        checkConfigurations(tokenIssuerConfig);

        Crypto signatureCrypto = tokenIssuerConfig.getIssuerCrypto(this.getClass().getClassLoader());
        Assert.assertEquals(signatureCrypto.getClass().getName(), "org.apache.wss4j.common.crypto.Merlin");

    }

    public void testTokenIssuerConfigurationsUsingFile() throws XMLStreamException, TrustException {

        this.isConfigFromFile = true;
        SAMLTokenIssuerConfig tokenIssuerConfig = CommonUtil.createTokenIssuerConfiguration(configurationFileName);
        Assert.assertNotNull(tokenIssuerConfig);
        checkConfigurations(tokenIssuerConfig);
    }

    public void testTokenIssuerConfigurationsUsingParameter() throws XMLStreamException, TrustException {

        this.isConfigFromFile = false;
        OMElement element = AXIOMUtil.stringToOM(this.configurationElement);
        Parameter parameter = new Parameter();
        parameter.setParameterElement(element);
        SAMLTokenIssuerConfig tokenIssuerConfig = CommonUtil.createTokenIssuerConfiguration(parameter);
        Assert.assertNotNull(tokenIssuerConfig);
        checkConfigurations(tokenIssuerConfig);
    }

    public void testGetDecryptedBytes() throws Exception {

        RahasData rahasData = new RahasData();
        byte[] ephemeralKey = TokenIssuerUtil.getSharedSecret(
                rahasData, 1, 192);

        Document doc = TestUtil.getTestDocument();

        WSSecHeader secHeader = new WSSecHeader(doc);
        secHeader.insertSecurityHeader();

        WSSecEncrypt builder = new WSSecEncrypt(secHeader);
        builder.setUserInfo("apache");
        builder.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
        builder.setSymmetricEncAlgorithm(WSConstants.TRIPLE_DES);

        SecretKey symmetricKey = KeyUtils.prepareSecretKey(WSConstants.TRIPLE_DES, ephemeralKey);

        builder.prepare(TestUtil.getCrypto(), symmetricKey);

        List<WSEncryptionPart> parts = new ArrayList<WSEncryptionPart>();
        WSEncryptionPart encP =
            new WSEncryptionPart(
                "add", "http://ws.apache.org/counter/counter_port_type", "Element"
            );
        parts.add(encP);

        Element refs = builder.encryptForRef(null, parts, symmetricKey);
        builder.addInternalRefElement(refs);

        /*
         * now add (prepend) the EncryptedKey element, then a
         * BinarySecurityToken if one was setup during prepare
         */
        builder.prependToHeader();

        builder.prependBSTElementToHeader();

        Element element = builder.getEncryptedKeyElement();

        byte[] decryptedKey = CommonUtil.getDecryptedBytes(new TestCallbackHandler(), TestUtil.getCrypto(), element, new RequestData());

        Assert.assertTrue(Arrays.equals(ephemeralKey, decryptedKey));

	// FIXME - need a test case for disabling BSP compliance on WSS4J
        // byte[] decryptedKey2 = CommonUtil.getDecryptedBytes(new TestCallbackHandler(), TestUtil.getCrypto(), element, true);
        // Assert.assertTrue(Arrays.equals(ephemeralKey, decryptedKey2));

    }

    public void testGetSymmetricKeyBasedKeyInfo() throws Exception {

        RahasData rahasData = new RahasData();

        Document doc = TestUtil.getTestDocument();

        KeyInfo keyInfo = CommonUtil.getSymmetricKeyBasedKeyInfo(doc, rahasData,
                TestUtil.getDefaultCertificate(), 256, TestUtil.getCrypto(), 2);

        Assert.assertNotNull(keyInfo);

        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(keyInfo).marshall(keyInfo, doc.getDocumentElement());

        printElement(keyInfo.getDOM());

        OMElement element = (OMElement)keyInfo.getDOM();

        printElement(element);

        Assert.assertNotNull(rahasData.getEphmeralKey());

        Assert.assertNotNull(element.getChildrenWithLocalName("EncryptedKey"));
        Assert.assertNotNull(element.getChildrenWithLocalName("CipherData"));
        Assert.assertNotNull(element.getChildrenWithLocalName("CipherValue"));
    }

    public void testGetCertificateBasedKeyInfo() throws Exception {

        Document doc = TestUtil.getTestDocument();

        KeyInfo keyInfo = CommonUtil.getCertificateBasedKeyInfo(TestUtil.getDefaultCertificate());

        Assert.assertNotNull(keyInfo);

        XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(keyInfo).marshall(keyInfo, doc.getDocumentElement());

        printElement(keyInfo.getDOM());

        OMElement element = (OMElement)keyInfo.getDOM();

        printElement(element);

        Assert.assertNotNull(element.getChildrenWithLocalName("X509Data"));
        Assert.assertNotNull(element.getChildrenWithLocalName("X509Certificate"));

    }

    public void testGetSAMLCallbackHandlerWithObject() throws Exception {

        RahasData rahasData = new RahasData();

        this.isConfigFromFile = true;
        SAMLTokenIssuerConfig tokenIssuerConfig = CommonUtil.createTokenIssuerConfiguration(configurationFileName);
        Assert.assertNotNull(tokenIssuerConfig);
        checkConfigurations(tokenIssuerConfig);

        tokenIssuerConfig.setCallbackHandler(new TestSAMLCallbackHandler());

        SAMLCallbackHandler cb = CommonUtil.getSAMLCallbackHandler(tokenIssuerConfig, rahasData);

        Assert.assertTrue(cb instanceof TestSAMLCallbackHandler);
    }

    public void testGetSAMLCallbackHandlerWithCallbackName() throws Exception {

        RahasData rahasData = new RahasData();

        MessageContext messageContext = new MessageContext();
        messageContext.setAxisService(new AxisService("My Service"));

        rahasData.setInMessageContext(messageContext);

        this.isConfigFromFile = true;
        SAMLTokenIssuerConfig tokenIssuerConfig = CommonUtil.createTokenIssuerConfiguration(configurationFileName);
        Assert.assertNotNull(tokenIssuerConfig);
        checkConfigurations(tokenIssuerConfig);

        tokenIssuerConfig.setCallbackHandlerName("org.apache.rahas.test.util.TestSAMLCallbackHandler");

        SAMLCallbackHandler cb = CommonUtil.getSAMLCallbackHandler(tokenIssuerConfig, rahasData);

        Assert.assertTrue(cb instanceof TestSAMLCallbackHandler);
    }

}
