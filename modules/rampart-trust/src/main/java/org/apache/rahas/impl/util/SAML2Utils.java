/*
 * Copyright The Apache Software Foundation.
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
import org.apache.axiom.om.dom.DOMMetaFactory;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.xml.security.exceptions.XMLSecurityException;
import org.apache.xml.security.keys.KeyInfo;
import org.apache.xml.security.keys.content.X509Data;
import org.apache.xml.security.keys.content.x509.XMLX509Certificate;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.core.xml.XMLObject;
import org.opensaml.core.xml.io.Marshaller;
import org.opensaml.core.xml.io.MarshallingException;
import org.opensaml.core.xml.io.Unmarshaller;
import org.opensaml.core.xml.io.UnmarshallerFactory;
import org.opensaml.core.xml.io.UnmarshallingException;
import org.opensaml.saml.saml2.core.Assertion;
import org.opensaml.saml.saml2.core.AttributeStatement;
import org.opensaml.saml.saml2.core.AuthnStatement;
import org.opensaml.saml.saml2.core.Conditions;
import org.opensaml.saml.saml2.core.Issuer;
import org.opensaml.saml.saml2.core.NameID;
import org.opensaml.saml.saml2.core.Subject;
import org.opensaml.saml.saml2.core.SubjectConfirmation;
import org.opensaml.saml.saml2.core.SubjectConfirmationData;
import org.opensaml.saml.common.SAMLVersion;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.config.InitializationException;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.w3c.dom.Text;
import org.xml.sax.SAXException;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.util.List;
import java.util.UUID;
import java.util.Base64;

public class SAML2Utils {

    private static final Log log = LogFactory.getLog(SAML2Utils.class);

    public static Element getElementFromAssertion(XMLObject xmlObj) throws TrustException {
        try {
            
            Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(xmlObj);
            Element assertionElement = marshaller.marshall(xmlObj,
                    ((DOMMetaFactory)OMAbstractFactory.getMetaFactory(OMAbstractFactory.FEATURE_DOM)).newDocumentBuilderFactory().newDocumentBuilder().newDocument());

            log.debug("DOM element is created successfully from the OpenSAML2 XMLObject");
            return assertionElement;

        } catch (Exception e) {
            throw new TrustException("Error creating DOM object from the assertion", e);
        }
    }

    /**
     * Extract certificates or the key available in the SAMLAssertion
     *
     * @param elem  The element to process.
     * @param crypto The crypto properties.
     * @param cb Callback class to get the Key
     * @return SAML2KeyInfo the SAML2 Key Info
     * @throws org.apache.wss4j.common.ext.WSSecurityException If an error occurred while extracting KeyInfo.
     *
     */
    public static SAML2KeyInfo getSAML2KeyInfo(Element elem, Crypto crypto,
                                              CallbackHandler cb, RequestData requestData) throws WSSecurityException {
        Assertion assertion;

        //build the assertion by unmarhalling the DOM element.
        try {
            InitializationService.initialize();

            String keyInfoElementString = elem.toString();
            DocumentBuilderFactory documentBuilderFactory = DocumentBuilderFactory.newInstance();
            documentBuilderFactory.setNamespaceAware(true);
            DocumentBuilder docBuilder = documentBuilderFactory.newDocumentBuilder();
            Document document = docBuilder.parse(new ByteArrayInputStream(keyInfoElementString.trim().getBytes()));
            Element element = document.getDocumentElement();
            UnmarshallerFactory unmarshallerFactory = XMLObjectProviderRegistrySupport.getUnmarshallerFactory();
            Unmarshaller unmarshaller = unmarshallerFactory
                    .getUnmarshaller(element);
            assertion = (Assertion) unmarshaller
                    .unmarshall(element);
        }
        catch (InitializationException e) {
//[ERROR] /home/rlapache/axis-axis2-java-rampart/modules/rampart-trust/src/main/java/org/apache/rahas/impl/util/SAML2Utils.java:[123,60] incompatible types: java.lang.String cannot be converted to java.lang.Exception
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in bootstrapping");
        } catch (UnmarshallingException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (IOException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (SAXException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        } catch (ParserConfigurationException e) {
            throw new WSSecurityException(
                    WSSecurityException.ErrorCode.FAILURE, e, "Failure in unmarshelling the assertion");
        }
        return getSAML2KeyInfo(assertion, crypto, cb, requestData);

    }

    public static SAML2KeyInfo getSAML2KeyInfo(Assertion assertion, Crypto crypto,
                                               CallbackHandler cb, RequestData requestData) throws WSSecurityException {

        //First ask the cb whether it can provide the secret
        WSPasswordCallback pwcb = new WSPasswordCallback(assertion.getID(), WSPasswordCallback.CUSTOM_TOKEN);
        if (cb != null) {
            try {
                cb.handle(new Callback[]{pwcb});
            } catch (Exception e1) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e1, "noKey");
            }
        }

        byte[] key = pwcb.getKey();

        if (key != null) {
            return new SAML2KeyInfo(assertion, key);
        } else {
            // if the cb fails to provide the secret.
            try {
                // extract the subject
                Subject samlSubject = assertion.getSubject();
                if (samlSubject == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject)"});
                }

                // extract the subject confirmation element from the subject
                SubjectConfirmation subjectConf = samlSubject.getSubjectConfirmations().get(0);
                if (subjectConf == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject Confirmation)"});
                }

                // Get the subject confirmation data, KeyInfoConfirmationDataType extends SubjectConfirmationData.
                SubjectConfirmationData scData = subjectConf.getSubjectConfirmationData();
                
                if (scData == null) {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no Subject Confirmation Data)"});
                }

                // Get the SAML specific XML representation of the keyInfo object
                XMLObject KIElem = null;
                List<XMLObject> scDataElements = scData.getOrderedChildren();
                for (XMLObject xmlObj : scDataElements) {
                    if (xmlObj instanceof org.opensaml.xmlsec.signature.KeyInfo) {
                        KIElem = xmlObj;
                        break;
                    }
                }

                Element keyInfoElement;

                // Generate a DOM element from the XMLObject.
                if (KIElem != null) {

                    Marshaller marshaller = XMLObjectProviderRegistrySupport.getMarshallerFactory().getMarshaller(KIElem);
                    try {
                        keyInfoElement = marshaller.marshall(KIElem,
                                ((DOMMetaFactory)OMAbstractFactory.getMetaFactory(OMAbstractFactory.FEATURE_DOM)).newDocumentBuilderFactory().newDocumentBuilder().newDocument());
                    } catch (ParserConfigurationException ex) {
                        // We never get here
                        throw new Error(ex);
                    }

                } else {
                    throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                            "invalidSAML2Token", new Object[]{"for Signature (no key info element)"});
                }

                AttributeStatement attrStmt = assertion.getAttributeStatements().size() != 0 ?
                        assertion.getAttributeStatements().get(0) : null;
                AuthnStatement authnStmt = assertion.getAuthnStatements().size() != 0 ?
                        assertion.getAuthnStatements().get(0) : null;

                // if an attr stmt is present, then it has a symmetric key.
                if (attrStmt != null) {
                    NodeList children = keyInfoElement.getChildNodes();
                    int len = children.getLength();

                    for (int i = 0; i < len; i++) {
                        Node child = children.item(i);
                        if (child.getNodeType() != Node.ELEMENT_NODE) {
                            continue;
                        }
                        QName el = new QName(child.getNamespaceURI(), child.getLocalName());
                        if (el.equals(WSConstants.ENCRYPTED_KEY)) {

                            byte[] secret = CommonUtil.getDecryptedBytes(cb, crypto, child, requestData);

                            return new SAML2KeyInfo(assertion, secret);
                        } else if (el.equals(new QName(WSConstants.WST_NS, "BinarySecret"))) {
                            Text txt = (Text) child.getFirstChild();
                            return new SAML2KeyInfo(assertion, Base64.getDecoder().decode(txt.getData()));
                        }
                    }

                }

                // If an authn stmt is present then it has a public key.
                if (authnStmt != null) {

                    X509Certificate[] certs;
                    try {
                        KeyInfo ki = new KeyInfo(keyInfoElement, null);

                        if (ki.containsX509Data()) {
                            X509Data data = ki.itemX509Data(0);
                            XMLX509Certificate certElem = null;
                            if (data != null && data.containsCertificate()) {
                                certElem = data.itemCertificate(0);
                            }
                            if (certElem != null) {
                                X509Certificate cert = certElem.getX509Certificate();
                                certs = new X509Certificate[1];
                                certs[0] = cert;
                                return new SAML2KeyInfo(assertion, certs);
                            }
                        }

                    } catch (XMLSecurityException e3) {
                        throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e3, "invalidSAMLsecurity", new Object[]{"cannot get certificate (key holder)"});
                    }

                }


                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE,
                        "invalidSAMLsecurity",
                        new Object[]{"cannot get certificate or key "});

            } catch (MarshallingException e) {
                throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, e, "Failed marshalling the SAML Assertion", null);
            }
        }
    }

      /**
     * Get the subject confirmation method of a SAML 2.0 assertion
     *
     * @param assertion SAML 2.0 assertion
     * @return Subject Confirmation method
     */
    public static String getSAML2SubjectConfirmationMethod(Assertion assertion) {
        String subjectConfirmationMethod = RahasConstants.SAML20_SUBJECT_CONFIRMATION_HOK;
        List<SubjectConfirmation> subjectConfirmations = assertion.getSubject().getSubjectConfirmations();
        if (subjectConfirmations.size() > 0) {
            subjectConfirmationMethod = subjectConfirmations.get(0).getMethod();
        }
        return subjectConfirmationMethod;
    }


    public static Assertion createAssertion() throws TrustException {
        try {
            Assertion assertion = (Assertion)CommonUtil.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);
            assertion.setVersion(SAMLVersion.VERSION_20);

            // Set an UUID as the ID of an assertion
            assertion.setID(UUID.randomUUID().toString());
            return assertion;
        } catch (TrustException e) {
            throw new TrustException("Unable to create an Assertion object: " + e.getMessage(), e);
        }
    }

    public static Issuer createIssuer(String issuerName) throws TrustException {
        try {
            Issuer issuer = (Issuer)CommonUtil.buildXMLObject(Issuer.DEFAULT_ELEMENT_NAME);
            issuer.setValue(issuerName);
            return issuer;
        } catch (TrustException e) {
            throw new TrustException("Unable to create an Issuer object", e);
        }
    }

    public static Conditions createConditions(Instant creationTime, Instant expirationTime) throws TrustException {
        try {
            Conditions conditions = (Conditions)CommonUtil.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);
            conditions.setNotBefore(creationTime);
            conditions.setNotOnOrAfter(expirationTime);
            return conditions;
        } catch (TrustException e) {
            throw new TrustException("Unable to create an Conditions object");
        }
    }

/**
     * Create named identifier.
     * @param principalName Name of the subject.
     * @param format Format of the subject, whether it is an email, uid etc ...
     * @return The NamedIdentifier object.
     * @throws org.apache.rahas.TrustException If unable to find the builder.
     */
    public static NameID createNamedIdentifier(String principalName, String format) throws TrustException{

        NameID nameId = (NameID)CommonUtil.buildXMLObject(NameID.DEFAULT_ELEMENT_NAME);
        nameId.setValue(principalName);
        nameId.setFormat(format);

        return nameId;
    }


}


