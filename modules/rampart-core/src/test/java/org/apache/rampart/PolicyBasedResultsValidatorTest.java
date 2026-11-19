/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.rampart;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.Collections;
import java.util.Date;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import javax.security.auth.callback.CallbackHandler;

import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.crypto.CryptoType;
import org.apache.wss4j.common.bsp.BSPEnforcer;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.SupportingToken;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Tests the signature-wrapping defence in {@link PolicyBasedResultsValidator}
 * (RAMPART-428): the SOAP Body the application consumes must be the very element
 * that was signed, identified by node identity rather than by element name.
 */
public class PolicyBasedResultsValidatorTest extends TestCase {

    // -----------------------------------------------------------------------
    // isCertificateInKeyStore tests (RAMPART-461)
    // -----------------------------------------------------------------------

    /**
     * Concrete subclass that exposes the protected method under test.
     * No real crypto wiring is needed — we inject stub Crypto instances.
     */
    private static class Validator extends PolicyBasedResultsValidator {
        boolean callIsCertificateInKeyStore(Crypto crypto, X509Certificate cert) throws RampartException {
            return isCertificateInKeyStore(crypto, cert);
        }
    }

    /** Minimal Crypto stub whose getX509Certificates() is controlled by the caller. */
    private static class StubCrypto implements Crypto {
        private final X509Certificate[] returnValue;

        StubCrypto(X509Certificate[] returnValue) {
            this.returnValue = returnValue;
        }

        public X509Certificate[] getX509Certificates(CryptoType cryptoType) throws WSSecurityException {
            return returnValue;
        }

        // ---- All other Crypto methods are unused by isCertificateInKeyStore ----
        public String getCryptoProvider() { return null; }
        public void setCryptoProvider(String provider) {}
        public String getTrustProvider() { return null; }
        public void setTrustProvider(String provider) {}
        public String getDefaultX509Identifier() throws WSSecurityException { return null; }
        public void setDefaultX509Identifier(String identifier) {}
        public void setCertificateFactory(java.security.cert.CertificateFactory f) {}
        public java.security.cert.CertificateFactory getCertificateFactory() throws WSSecurityException { return null; }
        public X509Certificate loadCertificate(java.io.InputStream in) throws WSSecurityException { return null; }
        public byte[] getSKIBytesFromCert(X509Certificate cert) throws WSSecurityException { return null; }
        public byte[] getBytesFromCertificates(X509Certificate[] certs) throws WSSecurityException { return null; }
        public X509Certificate[] getCertificatesFromBytes(byte[] data) throws WSSecurityException { return null; }
        public String getX509Identifier(X509Certificate cert) throws WSSecurityException { return null; }
        public java.security.PrivateKey getPrivateKey(X509Certificate cert, CallbackHandler cb) throws WSSecurityException { return null; }
        public java.security.PrivateKey getPrivateKey(java.security.PublicKey publicKey, CallbackHandler cb) throws WSSecurityException { return null; }
        public java.security.PrivateKey getPrivateKey(String identifier, String password) throws WSSecurityException { return null; }
        public void verifyTrust(X509Certificate[] certs, boolean enableRevocation,
                java.util.Collection<java.util.regex.Pattern> subjectCertConstraints,
                java.util.Collection<java.util.regex.Pattern> issuerCertConstraints) throws WSSecurityException {}
        public void verifyTrust(java.security.PublicKey publicKey) throws WSSecurityException {}
    }

    /** Generates a fresh self-signed RSA certificate in memory. */
    private static X509Certificate generateSelfSignedCert() throws Exception {
        KeyPairGenerator kpg = KeyPairGenerator.getInstance("RSA");
        kpg.initialize(2048);
        KeyPair kp = kpg.generateKeyPair();

        X500Name name = new X500Name("CN=Test, O=Rampart, C=US");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis() - 1000L);
        Date notAfter  = new Date(System.currentTimeMillis() + 365L * 24 * 3600 * 1000);

        X509v3CertificateBuilder builder = new JcaX509v3CertificateBuilder(
                name, serial, notBefore, notAfter, name, kp.getPublic());
        ContentSigner signer = new JcaContentSignerBuilder("SHA256withRSA").build(kp.getPrivate());
        return new JcaX509CertificateConverter().getCertificate(builder.build(signer));
    }

    /**
     * RAMPART-461: WSS4J 2.x returns an empty array (never null) when no
     * certificate matches.  Before the fix, foundCerts[0] threw
     * ArrayIndexOutOfBoundsException.  After the fix it must return false.
     */
    public void testEmptyArrayReturnsFalse() throws Exception {
        Validator v = new Validator();
        X509Certificate cert = generateSelfSignedCert();
        // WSS4J 2.x: no match → empty array
        assertFalse("empty array must return false",
                v.callIsCertificateInKeyStore(new StubCrypto(new X509Certificate[0]), cert));
    }

    /** Null array (legacy / defensive) must return false without NPE. */
    public void testNullArrayReturnsFalse() throws Exception {
        Validator v = new Validator();
        X509Certificate cert = generateSelfSignedCert();
        assertFalse("null array must return false",
                v.callIsCertificateInKeyStore(new StubCrypto(null), cert));
    }

    /** When the keystore holds the exact same cert, return true. */
    public void testMatchingCertReturnsTrue() throws Exception {
        Validator v = new Validator();
        X509Certificate cert = generateSelfSignedCert();
        assertTrue("same cert must return true",
                v.callIsCertificateInKeyStore(new StubCrypto(new X509Certificate[]{cert}), cert));
    }

    /** When the keystore holds a different cert, return false. */
    public void testDifferentCertReturnsFalse() throws Exception {
        Validator v = new Validator();
        X509Certificate certA = generateSelfSignedCert();
        X509Certificate certB = generateSelfSignedCert();
        assertFalse("different cert must return false",
                v.callIsCertificateInKeyStore(new StubCrypto(new X509Certificate[]{certB}), certA));
    }

    // -----------------------------------------------------------------------
    // UsernameToken password type (RAMPART-463)
    // -----------------------------------------------------------------------

    private static final String WSSE_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd";
    private static final String WSU_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-utility-1.0.xsd";
    private static final String UT_PROFILE_NS =
            "http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-username-token-profile-1.0#";

    /**
     * Runs the supporting-token check for a policy asking for a clear-text (or,
     * with <code>hashPassword</code>, a digest) UsernameToken against a received
     * token whose wsse:Password carries the given attributes. The token is parsed
     * by WSS4J with BSP enforcement off, as under disableBSPEnforcement.
     */
    private void validateUsernameToken(String passwordAttributes, boolean hashPassword)
            throws Exception {
        // Nonce and Created are there because WSS4J will not parse a digest without them.
        String xml = "<wsse:UsernameToken xmlns:wsse='" + WSSE_NS + "' xmlns:wsu='" + WSU_NS + "'>"
                + "<wsse:Username>alice</wsse:Username>"
                + "<wsse:Password" + passwordAttributes + ">c2VjcmV0</wsse:Password>"
                + "<wsse:Nonce>bm9uY2U=</wsse:Nonce>"
                + "<wsu:Created>2026-01-01T00:00:00Z</wsu:Created>"
                + "</wsse:UsernameToken>";
        // Parsing a digest password needs the XML security library initialised.
        WSSConfig.init();
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setNamespaceAware(true);
        Element element = dbf.newDocumentBuilder()
                .parse(new ByteArrayInputStream(xml.getBytes(StandardCharsets.UTF_8)))
                .getDocumentElement();
        org.apache.wss4j.dom.message.token.UsernameToken received =
                new org.apache.wss4j.dom.message.token.UsernameToken(
                        element, false, new BSPEnforcer(true));

        org.apache.ws.secpolicy.model.UsernameToken policyToken =
                new org.apache.ws.secpolicy.model.UsernameToken(SPConstants.SP_V12);
        policyToken.setHashPassword(hashPassword);
        SupportingToken supportingTokens =
                new SupportingToken(SPConstants.SUPPORTING_TOKEN_SUPPORTING, SPConstants.SP_V12);
        supportingTokens.addToken(policyToken);

        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.UT, received);
        new Validator().handleSupportingTokens(
                null, Collections.singletonList(result), supportingTokens);
    }

    private void assertUsernameTokenRejected(String passwordAttributes, boolean hashPassword)
            throws Exception {
        try {
            validateUsernameToken(passwordAttributes, hashPassword);
            fail("expected the UsernameToken to be rejected");
        } catch (RampartException expected) {
            // WSS4J reports the same condition differently; only Rampart's verdict matters.
        }
    }

    /** RAMPART-463: this used to end in a NullPointerException. */
    public void testPasswordWithoutTypeIsClearText() throws Exception {
        validateUsernameToken("", false);
    }

    public void testPasswordWithEmptyTypeIsClearText() throws Exception {
        validateUsernameToken(" Type=''", false);
    }

    public void testPasswordTextTypeIsClearText() throws Exception {
        validateUsernameToken(" Type='" + UT_PROFILE_NS + "PasswordText'", false);
    }

    /** A digest must not pass where the policy asks for clear text. */
    public void testDigestRejectedWhereClearTextRequired() throws Exception {
        assertUsernameTokenRejected(" Type='" + UT_PROFILE_NS + "PasswordDigest'", false);
    }

    /** Nor may an unknown type be waved through as clear text. */
    public void testUnknownTypeRejectedWhereClearTextRequired() throws Exception {
        assertUsernameTokenRejected(" Type='urn:example:other'", false);
    }

    /** An untyped password is clear text, so it cannot satisfy a HashPassword policy. */
    public void testPasswordWithoutTypeRejectedWhereDigestRequired() throws Exception {
        assertUsernameTokenRejected("", true);
    }

    // -----------------------------------------------------------------------
    // Signature-wrapping tests (RAMPART-428) — unchanged below
    // -----------------------------------------------------------------------

    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";

    // A signature-wrapping layout: the original (signed) Body is relocated into a
    // <wrapper> inside the header, and a new arbitrary Body sits in the Body position.
    private static final String WRAPPED =
            "<env:Envelope xmlns:env='" + SOAP_NS + "'>"
          + "  <env:Header>"
          + "    <wrapper xmlns=''>"
          + "      <env:Body env:id='signed'><echo>original</echo></env:Body>"
          + "    </wrapper>"
          + "  </env:Header>"
          + "  <env:Body><echo>arbitrary</echo></env:Body>"
          + "</env:Envelope>";

    private Document doc;
    private Element realBody;     // the Body the application consumes (Body position)
    private Element wrappedBody;  // the relocated, signed Body

    protected void setUp() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Secure the parser (OWASP): no DTDs / external entities.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        doc = db.parse(new ByteArrayInputStream(WRAPPED.getBytes(StandardCharsets.UTF_8)));

        NodeList bodies = doc.getElementsByTagNameNS(SOAP_NS, "Body");
        assertEquals("test fixture should contain two Body elements", 2, bodies.getLength());
        // Document order: the wrapped (signed) Body comes first (inside the header),
        // the real consumed Body is the direct child of Envelope.
        wrappedBody = (Element) bodies.item(0);
        realBody = (Element) bodies.item(1);
        assertEquals("Envelope", realBody.getParentNode().getLocalName());
        assertEquals("wrapper", wrappedBody.getParentNode().getLocalName());
    }

    /** Wrapping attack: only the relocated copy is signed, so the real body must be rejected. */
    public void testWrappedBodyIsNotConsideredSigned() {
        assertFalse("a relocated same-name Body must not count as the signed body",
                PolicyBasedResultsValidator.isElementSigned(realBody, Collections.singletonList(wrappedBody)));
    }

    /** Legitimate case: the real consumed body is itself the signed element. */
    public void testActualSignedBodyIsAccepted() {
        assertTrue("the actual signed body must be recognised",
                PolicyBasedResultsValidator.isElementSigned(realBody, Collections.singletonList(realBody)));
    }

    /** Mixed set still matches by identity. */
    public void testAcceptedWhenRealBodyAmongSignedElements() {
        assertTrue(PolicyBasedResultsValidator.isElementSigned(
                realBody, Arrays.asList(wrappedBody, realBody)));
    }

    public void testNullInputsAreNotSigned() {
        assertFalse(PolicyBasedResultsValidator.isElementSigned(null, Collections.singletonList(realBody)));
        assertFalse(PolicyBasedResultsValidator.isElementSigned(realBody, null));
        assertFalse(PolicyBasedResultsValidator.isElementSigned(realBody, Collections.<Element>emptyList()));
    }
}
