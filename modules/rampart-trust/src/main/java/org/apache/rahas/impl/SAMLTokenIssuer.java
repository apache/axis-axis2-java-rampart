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

package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenIssuer;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.*;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.XmlSchemaDateFormat;

import org.joda.time.DateTime;
import org.opensaml.common.SAMLException;
import org.opensaml.saml1.core.*;
import org.opensaml.xml.signature.KeyInfo;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import java.security.Principal;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * Issuer to issue SAMl tokens
 */
public class SAMLTokenIssuer implements TokenIssuer {

    private String configParamName;

    private OMElement configElement;

    private String configFile;


    //TODO move this to TrustUtil
    private static final String  AUTHENTICATION_METHOD_PASSWORD = "urn:oasis:names:tc:SAML:1.0:am:password";

    private static final Log log = LogFactory.getLog(SAMLTokenIssuer.class);

    public SOAPEnvelope issue(RahasData data) throws TrustException {
        MessageContext inMsgCtx = data.getInMessageContext();

        SAMLTokenIssuerConfig config = null;
        if (this.configElement != null) {
            config = new SAMLTokenIssuerConfig(configElement
                            .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        // Look for the file
        if (config == null && this.configFile != null) {
            config = new SAMLTokenIssuerConfig(this.configFile);
        }

        // Look for the param
        if (config == null && this.configParamName != null) {
            Parameter param = inMsgCtx.getParameter(this.configParamName);
            if (param != null && param.getParameterElement() != null) {
                config = new SAMLTokenIssuerConfig(param
                        .getParameterElement().getFirstChildWithName(
                                SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
            } else {
                throw new TrustException("expectedParameterMissing",
                        new String[] { this.configParamName });
            }
        }

        if (config == null) {
            throw new TrustException("configurationIsNull");
        }

        SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
                .getEnvelope().getNamespace().getNamespaceURI());

        Crypto crypto;
        if (config.cryptoElement != null) { // crypto props defined as elements
            crypto = CommonUtil.getCrypto(TrustUtil
                    .toProperties(config.cryptoElement), inMsgCtx
                    .getAxisService().getClassLoader());

        } else { // crypto props defined in a properties file
            crypto = CommonUtil.getCrypto(config.cryptoPropertiesFile, inMsgCtx
                    .getAxisService().getClassLoader());
        }

        // Creation and expiration times
        DateTime creationTime = new DateTime();
        DateTime expirationTime = new DateTime(creationTime.getMillis() + config.ttl);

        // Get the document
        Document doc = ((Element) env).getOwnerDocument();

        // Get the key size and create a new byte array of that size
        int keySize = data.getKeysize();

        keySize = (keySize == -1) ? config.keySize : keySize;

        /*
         * Find the KeyType If the KeyType is SymmetricKey or PublicKey,
         * issue a SAML HoK assertion. - In the case of the PublicKey, in
         * coming security header MUST contain a certificate (maybe via
         * signature)
         * 
         * If the KeyType is Bearer then issue a Bearer assertion
         * 
         * If the key type is missing we will issue a HoK assertion
         */

        String keyType = data.getKeyType();
        Assertion assertion;
        if (keyType == null) {
            throw new TrustException(TrustException.INVALID_REQUEST,
                    new String[] { "Requested KeyType is missing" });
        }

        if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)
                || keyType.endsWith(RahasConstants.KEY_TYPE_PUBLIC_KEY)) {
            assertion = createHoKAssertion(config, doc, crypto,
                    creationTime, expirationTime, data);
        } else if (keyType.endsWith(RahasConstants.KEY_TYPE_BEARER)) {
            assertion = createBearerAssertion(config, doc, crypto,
                    creationTime, expirationTime, data);
        } else {
            throw new TrustException("unsupportedKeyType");
        }

        OMElement rstrElem;
        int wstVersion = data.getVersion();
        if (RahasConstants.VERSION_05_02 == wstVersion) {
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                    wstVersion, env.getBody());
        } else {
            OMElement rstrcElem = TrustUtil
                    .createRequestSecurityTokenResponseCollectionElement(
                            wstVersion, env.getBody());
            rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
                    wstVersion, rstrcElem);
        }

        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                RahasConstants.TOK_TYPE_SAML_10);

        if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)) {
            TrustUtil.createKeySizeElement(wstVersion, rstrElem, keySize);
        }

        if (config.addRequestedAttachedRef) {
            TrustUtil.createRequestedAttachedRef(rstrElem, assertion.getID(),wstVersion);
        }

        if (config.addRequestedUnattachedRef) {
            TrustUtil.createRequestedUnattachedRef(rstrElem, assertion.getID(),wstVersion);
        }

        if (data.getAppliesToAddress() != null) {
            TrustUtil.createAppliesToElement(rstrElem, data
                    .getAppliesToAddress(), data.getAddressingNs());
        }

        // Use GMT time in milliseconds
        DateFormat zulu = new XmlSchemaDateFormat();

        // Add the Lifetime element
        TrustUtil.createLifetimeElement(wstVersion, rstrElem, zulu
                .format(creationTime.toDate()), zulu.format(expirationTime.toDate()));

        // Create the RequestedSecurityToken element and add the SAML token
        // to it
        OMElement reqSecTokenElem = TrustUtil
                .createRequestedSecurityTokenElement(wstVersion, rstrElem);
        Token assertionToken;
        //try {
            Node tempNode = assertion.getDOM();
            reqSecTokenElem.addChild((OMNode) ((Element) rstrElem)
                    .getOwnerDocument().importNode(tempNode, true));

            // Store the token
            assertionToken = new Token(assertion.getID(),
                    (OMElement) assertion.getDOM(), creationTime.toDate(),
                    expirationTime.toDate());

            // At this point we definitely have the secret
            // Otherwise it should fail with an exception earlier
            assertionToken.setSecret(data.getEphmeralKey());
            TrustUtil.getTokenStore(inMsgCtx).add(assertionToken);

       /* } catch (SAMLException e) {
            throw new TrustException("samlConverstionError", e);
        }*/

        if (keyType.endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)
                && config.keyComputation != SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_USE_REQ_ENT) {

            // Add the RequestedProofToken
            TokenIssuerUtil.handleRequestedProofToken(data, wstVersion,
                    config, rstrElem, assertionToken, doc);
        }

        return env;
    }



    private Assertion createBearerAssertion(SAMLTokenIssuerConfig config,
                                            Document doc, Crypto crypto, DateTime creationTime,
                                            DateTime expirationTime, RahasData data) throws TrustException {

        Principal principal = data.getPrincipal();
        Assertion assertion;
        // In the case where the principal is a UT
        if (principal instanceof WSUsernameTokenPrincipal) {
            NameIdentifier nameId = null;
            if (config.getCallbackHandler() != null) {
                SAMLNameIdentifierCallback cb = new SAMLNameIdentifierCallback(data);
                cb.setUserId(principal.getName());
                SAMLCallbackHandler callbackHandler = config.getCallbackHandler();
                try {
                    callbackHandler.handle(cb);
                } catch (SAMLException e) {
                    throw new TrustException("unableToRetrieveCallbackHandler", e);
                }
                nameId = cb.getNameId();
            } else {

                nameId = SAMLUtils.createNamedIdentifier(principal.getName(), NameIdentifier.EMAIL);
            }

            assertion = createAuthAssertion(RahasConstants.SAML11_SUBJECT_CONFIRMATION_BEARER,
                    nameId, null, config, crypto, creationTime,
                    expirationTime, data);
            return assertion;
        } else {
            throw new TrustException("samlUnsupportedPrincipal",
                    new String[]{principal.getClass().getName()});
        }
    }

    private Assertion createHoKAssertion(SAMLTokenIssuerConfig config,
            Document doc, Crypto crypto, DateTime creationTime,
            DateTime expirationTime, RahasData data) throws TrustException {

        if (data.getKeyType().endsWith(RahasConstants.KEY_TYPE_SYMM_KEY)) {
            X509Certificate serviceCert = null;
            try {

                // TODO what if principal is null ?
                NameIdentifier nameIdentifier = null;
                if (data.getPrincipal() != null) {
                    String subjectNameId = data.getPrincipal().getName();
                    nameIdentifier =SAMLUtils.createNamedIdentifier(subjectNameId, NameIdentifier.EMAIL);
                }

                /**
                 * In this case we need to create a KeyInfo similar to following,
                 * *  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                 *     <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                 *           ....
                 *     </xenc:EncryptedKey>
                 *   </ds:KeyInfo>
                 */

                // Get ApliesTo to figure out which service to issue the token
                // for
                serviceCert = getServiceCert(config, crypto, data
                        .getAppliesToAddress());

                // set keySize
                int keySize = data.getKeysize();
                keySize = (keySize != -1) ? keySize : config.keySize;

                // Create the encrypted key
                KeyInfo encryptedKeyInfoElement
                        = SAMLUtils.getSymmetricKeyBasedKeyInfo(doc, data, serviceCert, keySize,
                        crypto, config.keyComputation);

                return this.createAttributeAssertion(data, encryptedKeyInfoElement, nameIdentifier, config,
                    crypto, creationTime, expirationTime);


            } catch (WSSecurityException e) {

                if (serviceCert != null) {
                    throw new TrustException(
                            "errorInBuildingTheEncryptedKeyForPrincipal",
                            new String[]{serviceCert.getSubjectDN().getName()},
                            e);
                } else {
                    throw new TrustException(
                            "trustedCertNotFoundForEPR",
                            new String[]{data.getAppliesToAddress()},
                            e);
                }

            }
        } else {
            try {

                /**
                 * In this case we need to create KeyInfo as follows,
                 * <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
                 *   <X509Data xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
                 *             xmlns:ds="http://www.w3.org/2000/09/xmldsig#">
                 *        <X509Certificate>
                 *              MIICNTCCAZ6gAwIBAgIES343....
                 *           </X509Certificate>
                 *       </X509Data>
                 *   </KeyInfo>
                 */

                String subjectNameId = data.getPrincipal().getName();
                
                NameIdentifier nameId = SAMLUtils.createNamedIdentifier(subjectNameId, NameIdentifier.EMAIL);

                // Create the ds:KeyValue element with the ds:X509Data
                X509Certificate clientCert = data.getClientCert();

                if(clientCert == null) {
                    clientCert = CommonUtil.getCertificateByAlias(crypto,data.getPrincipal().getName());;
                }

                KeyInfo keyInfo = SAMLUtils.getCertificateBasedKeyInfo(clientCert);

                return this.createAuthAssertion(RahasConstants.SAML11_SUBJECT_CONFIRMATION_HOK, nameId, keyInfo,
                        config, crypto, creationTime, expirationTime, data);
            } catch (Exception e) {
                throw new TrustException("samlAssertionCreationError", e);
            }
        }
    }

    /**
     * Uses the <code>wst:AppliesTo</code> to figure out the certificate to
     * encrypt the secret in the SAML token
     * 
     * @param config Token issuer configuration.
     * @param crypto Crypto properties.
     * @param serviceAddress
     *            The address of the service
     * @return The X509 certificate.
     * @throws org.apache.rahas.TrustException If an error occurred while retrieving certificate from crypto.
     */
    private X509Certificate getServiceCert(SAMLTokenIssuerConfig config,
            Crypto crypto, String serviceAddress) throws TrustException {

        // TODO a duplicate method !!
        if (serviceAddress != null && !"".equals(serviceAddress)) {
            String alias = (String) config.trustedServices.get(serviceAddress);
            if (alias != null) {
                return CommonUtil.getCertificateByAlias(crypto,alias);
            } else {
                alias = (String) config.trustedServices.get("*");
                return CommonUtil.getCertificateByAlias(crypto,alias);
            }
        } else {
            String alias = (String) config.trustedServices.get("*");
            return CommonUtil.getCertificateByAlias(crypto,alias);
        }

    }

    /**
     * Create the SAML assertion with the secret held in an
     * <code>xenc:EncryptedKey</code>
     * @param data The Rahas configurations, this is needed to get the callbacks.
     * @param keyInfo OpenSAML KeyInfo representation.
     * @param subjectNameId Principal as an OpenSAML Subject
     * @param config SAML Token issuer configurations.
     * @param crypto To get certificate information.
     * @param notBefore Validity period start.
     * @param notAfter Validity period end
     * @return OpenSAML Assertion object.
     * @throws TrustException If an error occurred while creating the Assertion.
     */
    private Assertion createAttributeAssertion(RahasData data,
                                               KeyInfo keyInfo, NameIdentifier subjectNameId,
                                               SAMLTokenIssuerConfig config,
                                               Crypto crypto, DateTime notBefore, DateTime notAfter) throws TrustException {
        try {

            Subject subject
                    = SAMLUtils.createSubject(subjectNameId, RahasConstants.SAML11_SUBJECT_CONFIRMATION_HOK, keyInfo);

            Attribute[] attrs;
            if (config.getCallbackHandler() != null) {
                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
                SAMLCallbackHandler handler = config.getCallbackHandler();
                handler.handle(cb);
                attrs = cb.getAttributes();
            } else if (config.getCallbackHandlerName() != null
                    && config.getCallbackHandlerName().trim().length() > 0) {
                SAMLAttributeCallback cb = new SAMLAttributeCallback(data);
                SAMLCallbackHandler handler = null;
                MessageContext msgContext = data.getInMessageContext();
                ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
                Class cbClass;
                try {
                    cbClass = Loader.loadClass(classLoader, config.getCallbackHandlerName());
                } catch (ClassNotFoundException e) {
                    throw new TrustException("cannotLoadPWCBClass", new String[]{config
                            .getCallbackHandlerName()}, e);
                }
                try {
                    handler = (SAMLCallbackHandler) cbClass.newInstance();
                } catch (java.lang.Exception e) {
                    throw new TrustException("cannotCreatePWCBInstance", new String[]{config
                            .getCallbackHandlerName()}, e);
                }
                handler.handle(cb);
                attrs = cb.getAttributes();
            } else {
                //TODO Remove this after discussing
                Attribute attribute = SAMLUtils.createAttribute("Name", "https://rahas.apache.org/saml/attrns",
                        "Colombo/Rahas");
                attrs = new Attribute[]{attribute};
            }

            AttributeStatement attributeStatement = SAMLUtils.createAttributeStatement(subject, Arrays.asList(attrs));


            List<Statement> attributeStatements = new ArrayList<Statement>();
            attributeStatements.add(attributeStatement);

            Assertion assertion = SAMLUtils.createAssertion(config.issuerName, notBefore,
                    notAfter, attributeStatements);

            SAMLUtils.signAssertion(assertion, crypto, config.getIssuerKeyAlias(), config.getIssuerKeyPassword());

            return assertion;
        } catch (Exception e) {
            throw new TrustException("samlAssertionCreationError", e);
        }
    }

    /**
     * Creates an authentication assertion.
     * @param confirmationMethod The confirmation method. (HOK, Bearer ...)
     * @param subjectNameId The principal name.
     * @param keyInfo OpenSAML representation of KeyInfo.
     * @param config Rahas configurations.
     * @param crypto Certificate information.
     * @param notBefore Validity start.
     * @param notAfter Validity end.
     * @param data Other Rahas data.
     * @return An openSAML Assertion.
     * @throws TrustException If an exception occurred while creating the Assertion.
     */
    private Assertion createAuthAssertion(String confirmationMethod,
            NameIdentifier subjectNameId, KeyInfo keyInfo,
            SAMLTokenIssuerConfig config, Crypto crypto, DateTime notBefore,
            DateTime notAfter, RahasData data) throws TrustException {
        try {

            Subject subject = SAMLUtils.createSubject(subjectNameId,confirmationMethod, keyInfo);

            AuthenticationStatement authenticationStatement
                    = SAMLUtils.createAuthenticationStatement(subject, AUTHENTICATION_METHOD_PASSWORD,
                    notBefore);

            List<Statement> statements = new ArrayList<Statement>();
            if (data.getClaimDialect() != null && data.getClaimElem() != null) {
                Statement attrStatement = createSAMLAttributeStatement(
                        SAMLUtils.createSubject(subject.getNameIdentifier(),
                                confirmationMethod, keyInfo), data, config);
                statements.add(attrStatement);
            }

            statements.add(authenticationStatement);

            Assertion assertion = SAMLUtils.createAssertion(config.issuerName,
                    notBefore, notAfter, statements);

            // Signing the assertion
            // The <ds:Signature>...</ds:Signature> element appears only after
            // signing.
            SAMLUtils.signAssertion(assertion, crypto, config.getIssuerKeyAlias(), config.getIssuerKeyPassword());

            return assertion;
        } catch (Exception e) {
            throw new TrustException("samlAssertionCreationError", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public String getResponseAction(RahasData data) throws TrustException {
        return TrustUtil.getActionValue(data.getVersion(),
                RahasConstants.RSTR_ACTION_ISSUE);
    }

    /**
     * Create an ephemeral key
     * 
     * @return The generated key as a byte array
     * @throws TrustException
     */
    protected byte[] generateEphemeralKey(int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("Error in creating the ephemeral key", e);
        }
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationFile(String configFile) {
        this.configFile = configFile;

    }
    
    /**
     * {@inheritDoc}
     */
    public void setConfigurationElement(OMElement configElement) {
        this.configElement = configElement;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationParamName(String configParamName) {
        this.configParamName = configParamName;
    }

    private AttributeStatement createSAMLAttributeStatement(Subject subject,
                                                            RahasData rahasData,
                                                            SAMLTokenIssuerConfig config)
            throws TrustException {
        Attribute[] attrs = null;
        if (config.getCallbackHandler() != null) {
            SAMLAttributeCallback cb = new SAMLAttributeCallback(rahasData);
            SAMLCallbackHandler handler = config.getCallbackHandler();
            try {
                handler.handle(cb);
                attrs = cb.getAttributes();
            } catch (SAMLException e) {
                throw new TrustException("unableToRetrieveCallbackHandler", e);
            }

        } else if (config.getCallbackHandlerName() != null
                && config.getCallbackHandlerName().trim().length() > 0) {
            SAMLAttributeCallback cb = new SAMLAttributeCallback(rahasData);
            SAMLCallbackHandler handler = null;
            MessageContext msgContext = rahasData.getInMessageContext();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();
            Class cbClass = null;
            try {
                cbClass = Loader.loadClass(classLoader, config.getCallbackHandlerName());
            } catch (ClassNotFoundException e) {
                throw new TrustException("cannotLoadPWCBClass",
                        new String[]{config.getCallbackHandlerName()}, e);
            }
            try {
                handler = (SAMLCallbackHandler) cbClass.newInstance();
            } catch (Exception e) {
                throw new TrustException("cannotCreatePWCBInstance",
                        new String[]{config.getCallbackHandlerName()}, e);
            }
            try {
                handler.handle(cb);
            } catch (SAMLException e) {
                throw new TrustException("unableToRetrieveCallbackHandler", e);
            }
            attrs = cb.getAttributes();
        } else {
            //TODO Remove this after discussing
            Attribute attribute =
                    SAMLUtils.createAttribute("Name", "https://rahas.apache.org/saml/attrns", "Colombo/Rahas");

            attrs = new Attribute[]{attribute};
        }

        AttributeStatement attributeStatement = SAMLUtils.createAttributeStatement(subject, Arrays.asList(attrs));

        return attributeStatement;

    }

}
