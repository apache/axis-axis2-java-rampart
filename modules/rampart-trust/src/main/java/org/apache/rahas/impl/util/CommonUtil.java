/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

package org.apache.rahas.impl.util;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.dom.DOMMetaFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.SAMLTokenIssuerConfig;
import org.apache.ws.security.WSDocInfo;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.processor.EncryptedKeyProcessor;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.Properties;

import static org.apache.axiom.om.OMAbstractFactory.FEATURE_DOM;

/**
 * This class implements some utility methods common to SAML1 and SAML2.
 */
public class CommonUtil {

    private static Log log = LogFactory.getLog(CommonUtil.class);

    /**
     * This method creates a DOM compatible Axiom document.
     * @return DOM compatible Axiom document
     * @throws TrustException If an error occurred while creating the Document.
     */
    public static Document getOMDOMDocument() throws TrustException {
        DOMMetaFactory metaFactory = (DOMMetaFactory) OMAbstractFactory.getMetaFactory(FEATURE_DOM);
            DocumentBuilderFactory dbf = metaFactory.newDocumentBuilderFactory();
        try {
            return  dbf.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new TrustException("Error creating Axiom compatible DOM Document", e);
        }
    }

    /**
     * Gets the certificates chain by alias. Always returns the first certificate if a certificate chain is found.
     * @param crypto Crypto to lookup certificate.
     * @param alias Alias name.
     * @return X509 certificate object.
     * @throws org.apache.rahas.TrustException If an error occurred
     *                              while retrieving the certificate or if no certificates are found for given alias.
     */
    public static X509Certificate getCertificateByAlias(Crypto crypto, String alias) throws TrustException {

        X509Certificate[] certificates = getCertificatesByAlias(crypto, alias);

        if (certificates == null) {
            log.error("Unable to retrieve certificate for alias " + alias);
            throw new TrustException("issuerCertificateNotFound");
        }

        return certificates[0];
    }

    /**
     * Gets the certificates chain by alias. If no certificates are found return an empty array.
     * @param crypto Crypto to lookup certificate.
     * @param alias Alias name.
     * @return X509 certificates array.
     * @throws org.apache.rahas.TrustException If an error occurred
     *                                          while retrieving the certificate.
     */
    public static X509Certificate[] getCertificatesByAlias(Crypto crypto, String alias) throws TrustException {

        // TODO are we always looking up by alias ? Dont we need to lookup by any other attribute ?
        CryptoType type = new CryptoType(CryptoType.TYPE.ALIAS);
        type.setAlias(alias);

        try {
            X509Certificate[] certificates = crypto.getX509Certificates(type);

            if (certificates == null) {
                log.debug("Unable to retrieve certificate for alias " + alias);
                return new X509Certificate[0];
            }
            return certificates;
        } catch (WSSecurityException e) {
            log.error("Unable to retrieve certificate for alias " + alias, e);
            throw new TrustException("issuerCertificateNotFound", e);
        }
    }

    /**
     * Decrypts the EncryptedKey element and returns the secret that was used.
     * @param callbackHandler Callback handler to pass to WSS4J framework.
     * @param crypto To get private key information.
     * @param encryptedKeyElement The encrypted Key element.
     * @return The secret as a byte stream.
     * @throws WSSecurityException If an error is occurred while decrypting the element.
     */
    public static byte[] getDecryptedBytes(CallbackHandler callbackHandler, Crypto crypto, Node encryptedKeyElement)
            throws WSSecurityException {

        // TODO make this code more efficient and reader friendly

        EncryptedKeyProcessor encryptedKeyProcessor = new EncryptedKeyProcessor();

        RequestData requestData = new RequestData();
        requestData.setCallbackHandler(callbackHandler);
        requestData.setDecCrypto(crypto);

        final WSSConfig cfg = WSSConfig.getNewInstance();
        requestData.setWssConfig(cfg);

        WSDocInfo docInfo = new WSDocInfo(encryptedKeyElement.getOwnerDocument());

        List<WSSecurityEngineResult> resultList
                = null;

        resultList = encryptedKeyProcessor.handleToken((Element) encryptedKeyElement, requestData, docInfo);


        WSSecurityEngineResult wsSecurityEngineResult = resultList.get(0);

        return (byte[]) wsSecurityEngineResult.get(WSSecurityEngineResult.TAG_SECRET);
    }

    /**
     * Constructs crypto configuration based on the given properties. Provider is instantiated using
     * given class loader.
     * @param properties Crypto configuration properties.
     * @param classLoader Class loader used to create provider.
     * @return A crypto object.
     * @throws TrustException If an error occurred while creating the Crypto object.
     */
    public static Crypto getCrypto(Properties properties, ClassLoader classLoader) throws TrustException {
        try {
            return CryptoFactory.getInstance(properties, classLoader);
        } catch (WSSecurityException e) {
            log.error("An error occurred while loading crypto properties", e);
            throw new TrustException("errorLoadingCryptoProperties", e);

        }
    }

    /**
     * Constructs crypto configuration based on the given properties. Provider is instantiated using
     * given class loader.
     * @param propertiesFile Crypto configuration properties file name.
     * @param classLoader Class loader used to create provider.
     * @return A crypto object.
     * @throws TrustException If an error occurred while creating the Crypto object.
     */
    public static Crypto getCrypto(String propertiesFile, ClassLoader classLoader) throws TrustException {
        try {
            return CryptoFactory.getInstance(propertiesFile, classLoader);
        } catch (WSSecurityException e) {
            log.error("An error occurred while loading crypto properties with property file " + propertiesFile, e);
            throw new TrustException("errorLoadingCryptoProperties", new Object[]{propertiesFile}, e);

        }
    }

    /**
     * Creates the token issuer configuration. The configuration is created in following order,
     * 1. Try create token configuration using configuration OMElement
     * 2. Try create token configuration using a configuration file name
     * 3. Try create token configuration using a parameter name in message context.
     * The issuer configuration would look like as follows,
     *
     *  <saml-issuer-config>
     *       <issuerName>Test_STS</issuerName>
     *       <issuerKeyAlias>ip</issuerKeyAlias>
     *       <issuerKeyPassword>password</issuerKeyPassword>
     *       <cryptoProperties>
     *          <crypto provider="org.apache.ws.security.components.crypto.Merlin">
     *               <property name="org.apache.ws.security.crypto.merlin.keystore.type">JKS</property>
     *               <property name="org.apache.ws.security.crypto.merlin.file">META-INF/rahas-sts.jks</property>
     *               <property name="org.apache.ws.security.crypto.merlin.keystore.password">password</property>
     *           </crypto>
     *       </cryptoProperties>
     *       <timeToLive>300000</timeToLive>
     *       <keySize>256</keySize>
     *       <addRequestedAttachedRef />
     *       <addRequestedUnattachedRef />
     *       <keyComputation>2</keyComputation>
     *       <proofKeyType>BinarySecret</proofKeyType>
     *       <trusted-services>
     *           <service alias="bob">http://localhost:8080/axis2/services/STS</service>
     *       </trusted-services>
     *   </saml-issuer-config>
     *
     * @param configElement Configuration as an OMElement.
     * @param configFile Configuration as a file.
     * @param messageContextParameter Configuration as a message context parameter.
     * @return  Token issuer configuration as a SAMLTokenIssuerConfig object.
     * @throws TrustException If an error occurred while creating SAMLTokenIssuerConfig object.
     */
    public static SAMLTokenIssuerConfig getTokenIssuerConfiguration(OMElement configElement, String configFile,
                                                               Parameter messageContextParameter) throws TrustException {

        // First try using configuration element
        SAMLTokenIssuerConfig tokenIssuerConfiguration = createTokenIssuerConfiguration(configElement);

        if (tokenIssuerConfiguration == null) {

            // Now try file
            tokenIssuerConfiguration = createTokenIssuerConfiguration(configFile);

            if (tokenIssuerConfiguration == null) {

                // Finally try using the parameter
                if (messageContextParameter != null) {
                    tokenIssuerConfiguration = createTokenIssuerConfiguration(messageContextParameter);
                }

                return tokenIssuerConfiguration;
            } else {
                return tokenIssuerConfiguration;
            }

        } else {
            return tokenIssuerConfiguration;
        }
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(OMElement configElement)
            throws TrustException {

        if (configElement != null) {

            log.debug("Creating token issuer configuration using OMElement");

            return new SAMLTokenIssuerConfig(configElement
                    .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        return null;
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(String configFile) throws TrustException {

        if (configFile != null) {

            if (log.isDebugEnabled()) {
                log.debug("Creating token issuer configuration using file " + configFile);
            }

            return new SAMLTokenIssuerConfig(configFile);
        }

        return null;
    }

    protected static SAMLTokenIssuerConfig createTokenIssuerConfiguration(Parameter messageContextParameter)
            throws TrustException {

        if (messageContextParameter != null && messageContextParameter.getParameterElement() != null) {

            log.debug("Creating token issuer configuration using the config parameter");

            return new SAMLTokenIssuerConfig(messageContextParameter
                    .getParameterElement().getFirstChildWithName(
                            SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        return null;
    }
}
