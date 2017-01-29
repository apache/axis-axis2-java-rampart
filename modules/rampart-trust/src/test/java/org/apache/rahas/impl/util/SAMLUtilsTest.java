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

import junit.framework.Assert;
import junit.framework.TestCase;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.Rahas;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.test.util.AbstractTestCase;
import org.apache.rahas.test.util.TestUtil;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.util.Base64;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml1.core.*;
import org.opensaml.xml.io.MarshallerFactory;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.signature.X509Data;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.xml.sax.SAXException;

import javax.xml.namespace.QName;
import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;
import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.*;
import java.security.SecureRandom;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

/**
 * A test class for SAML 1 Token Issuer.
 */
public class SAMLUtilsTest extends AbstractTestCase {

    private static final Log log = LogFactory.getLog(SAMLUtilsTest.class);

    public void testBuildXMLObjectNegative() {
        try {
            CommonUtil.buildXMLObject(new QName("http://x.com", "y"));
            Assert.fail("This should throw an exception");
        } catch (TrustException e) {
        }
    }

    public void testCreateSubjectConfirmationMethod()
            throws TrustException, MarshallingException, TransformerException {
        ConfirmationMethod confirmationMethod
                = SAMLUtils.createSubjectConfirmationMethod("urn:oasis:names:tc:SAML:1.0:cm:holder-of-key");

        marshallerFactory.getMarshaller(confirmationMethod).marshall(confirmationMethod);
        Assert.assertNotNull(confirmationMethod.getDOM());

        try {
            printElement(confirmationMethod.getDOM());
        } catch (TransformerException e) {
            log.error("Error printing SAML element", e);
            throw e;
        }
    }

    public void testCreateKeyInfo() {
        //TODO
    }

    public void testConditions() throws TrustException, MarshallingException, TransformerException {
        Conditions conditions = SAMLUtils.createConditions(new DateTime(), new DateTime(2050, 1, 1, 0, 0, 0, 0));

        marshallerFactory.getMarshaller(conditions).marshall(conditions);
        Assert.assertNotNull(conditions.getDOM());

        try {
            printElement(conditions.getDOM());
        } catch (TransformerException e) {
            log.error("Error printing SAML element", e);
            throw e;
        }
    }

    public void testCreateSubject() {
        //TODO
    }

    public void testCreateAuthenticationStatement(){
        //TODO
    }

    public void testSignAssertion() throws Exception {

        Assertion assertion = getAssertion();

        SAMLUtils.signAssertion(assertion, TestUtil.getCrypto(), "apache", "password");

        //marshallerFactory.getMarshaller(assertion).marshall(assertion);

        Assert.assertNotNull(assertion.getDOM());
        printElement(assertion.getDOM());

        boolean signatureFound = false;
        int numberOfNodes = assertion.getDOM().getChildNodes().getLength();
        for(int i=0; i < numberOfNodes; ++i) {

            OMElement n = (OMElement)assertion.getDOM().getChildNodes().item(i);

            if (n.getLocalName().equals("Signature")) {
                signatureFound = true;
                break;
            }
        }

        Assert.assertTrue("Signature not found.", signatureFound);
    }

    public void testCreateKeyInfoWithEncryptedKey() throws Exception {

        WSSecEncryptedKey encryptedKey = getWSEncryptedKey();

        org.opensaml.xml.encryption.EncryptedKey samlEncryptedKey
                = SAMLUtils.createEncryptedKey(getTestCertificate(), encryptedKey);

        org.opensaml.xml.signature.KeyInfo keyInfo = SAMLUtils.createKeyInfo(samlEncryptedKey);

        marshallerFactory.getMarshaller(keyInfo).marshall(keyInfo);

        Assert.assertNotNull(keyInfo.getDOM());
        printElement(keyInfo.getDOM());
    }

    public void testCreateKeyInfoWithX509Data() throws Exception {

        X509Data x509Data = CommonUtil.createX509Data(getTestCertificate());

        org.opensaml.xml.signature.KeyInfo keyInfo = SAMLUtils.createKeyInfo(x509Data);

        marshallerFactory.getMarshaller(keyInfo).marshall(keyInfo);

        Assert.assertNotNull(keyInfo.getDOM());
        printElement(keyInfo.getDOM());
    }

    public void testCreateAssertion() throws Exception {

        Assertion assertion = getAssertion();
        marshallerFactory.getMarshaller(assertion).marshall(assertion);
        Assert.assertNotNull(assertion.getDOM());

        try {
            printElement(assertion.getDOM());
        } catch (TransformerException e) {
            log.error("Error printing SAML element", e);
            throw e;
        }
    }

    private Assertion getAssertion() throws Exception{

        Attribute attributeMemberLevel
                = SAMLUtils.createAttribute("MemberLevel", "http://www.oasis.open.org/Catalyst2002/attributes", "gold");

        Attribute email
                = SAMLUtils.createAttribute("E-mail",
                "http://www.oasis.open.org/Catalyst2002/attributes",
                "joe@yahoo.com");

        NameIdentifier nameIdentifier
                = SAMLUtils.createNamedIdentifier("joe,ou=people,ou=saml-demo,o=baltimore.com",
                                                    NameIdentifier.X509_SUBJECT);

        X509Data x509Data = CommonUtil.createX509Data(getTestCertificate());

        org.opensaml.xml.signature.KeyInfo keyInfo = SAMLUtils.createKeyInfo(x509Data);

        Subject subject
                = SAMLUtils.createSubject(nameIdentifier, "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key", keyInfo);

        AttributeStatement attributeStatement
                = SAMLUtils.createAttributeStatement(subject, Arrays.asList(attributeMemberLevel, email));

        List<Statement> statements = new ArrayList<Statement>();
        statements.add(attributeStatement);

        Assertion assertion
                = SAMLUtils.createAssertion("www.opensaml.org", new DateTime(),
                new DateTime(2050, 1, 1, 0, 0, 0, 0), statements);

        return assertion;

    }

    public void testCreateX509Data() throws Exception {

        X509Data x509Data = CommonUtil.createX509Data(getTestCertificate());
        Assert.assertNotNull(x509Data);

        marshallerFactory.getMarshaller(x509Data).marshall(x509Data);
        Assert.assertNotNull(x509Data.getDOM());

        // Check certificates are equal

        String base64Cert = Base64.encode(getTestCertificate().getEncoded());
        Assert.assertEquals(base64Cert, x509Data.getDOM().getFirstChild().getTextContent());

       /* try {
            printElement(x509Data.getDOM());
        } catch (TransformerException e) {
            log.error("Error printing SAML element", e);
            throw e;
        }*/

    }

    public void testGetSymmetricKeyBasedKeyInfoContent() throws Exception {

        WSSecEncryptedKey encryptedKey = getWSEncryptedKey();

        org.opensaml.xml.encryption.EncryptedKey samlEncryptedKey
                = SAMLUtils.createEncryptedKey(getTestCertificate(), encryptedKey);

        marshallerFactory.getMarshaller(samlEncryptedKey).marshall(samlEncryptedKey);
        printElement(samlEncryptedKey.getDOM());

        Assert.assertTrue(equals(getXMLString(samlEncryptedKey.getDOM()),
                getXMLString(encryptedKey.getEncryptedKeyElement())));

    }

    private static WSSecEncryptedKey getWSEncryptedKey() throws Exception {

        SOAPEnvelope env = TrustUtil.createSOAPEnvelope("http://schemas.xmlsoap.org/soap/envelope/");
        Document doc = ((Element) env).getOwnerDocument();

        byte [] ephemeralKey = generateEphemeralKey(256);

        WSSecEncryptedKey encryptedKey
                = CommonUtil.getSymmetricKeyBasedKeyInfoContent(doc,
                                            ephemeralKey, getTestCertificate(), TestUtil.getCrypto());

        Assert.assertNotNull(encryptedKey.getEncryptedKeyElement());
        //printElement(encryptedKey.getEncryptedKeyElement());

        return encryptedKey;
    }

    private static byte[] generateEphemeralKey(int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("errorCreatingSymmKey", e);
        }
    }




    private static X509Certificate getTestCertificate() throws IOException, WSSecurityException, TrustException {

        Crypto crypto =  TestUtil.getCrypto();

        return CommonUtil.getCertificateByAlias(crypto, "apache");
    }



    private static boolean equals(String element1, String element2) throws ParserConfigurationException, IOException, SAXException {

        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setNamespaceAware(true);
        dbf.setCoalescing(true);
        dbf.setIgnoringElementContentWhitespace(true);
        dbf.setIgnoringComments(true);
        DocumentBuilder db = dbf.newDocumentBuilder();

        Document doc1 = db.parse(new ByteArrayInputStream(element1.getBytes("UTF-8")));
        doc1.normalizeDocument();

        Document doc2 = db.parse(new ByteArrayInputStream(element1.getBytes("UTF-8")));
        doc2.normalizeDocument();

        return doc1.isEqualNode(doc2);
    }

}
