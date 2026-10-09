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
package org.apache.rahas;

import java.io.FileInputStream;
import java.io.InputStream;
import java.security.KeyStore;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

import junit.framework.TestCase;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;

/**
 * The STS principal and proof-key certificate must come only from verified
 * signature or UsernameToken results, never from a bare BinarySecurityToken.
 *
 * <p>Nothing validates a BST on its own: it need not be trusted and the sender need
 * not hold its private key. RahasData used to take a BST's SubjectDN as the
 * principal and its certificate as the client certificate, so a requestor could be
 * issued an assertion for any identity, bound to a certificate of its choosing.</p>
 */
public class RahasDataTest extends TestCase {

    private static final String RST =
            "<wst:RequestSecurityToken xmlns:wst=\"http://docs.oasis-open.org/ws-sx/ws-trust/200512\">"
            + "<wst:RequestType>http://docs.oasis-open.org/ws-sx/ws-trust/200512/Issue</wst:RequestType>"
            + "</wst:RequestSecurityToken>";

    /** Stands in for the certificate a verified signature was made with. */
    private X509Certificate signerCert;

    /** Stands in for an arbitrary certificate an attacker places in a BST. */
    private X509Certificate bstCert;

    protected void setUp() throws Exception {
        KeyStore keyStore = KeyStore.getInstance("JKS");
        try (InputStream in = new FileInputStream("src/test/resources/keystore.jks")) {
            keyStore.load(in, "password".toCharArray());
        }
        signerCert = (X509Certificate) keyStore.getCertificate("apache");

        try (InputStream in = new FileInputStream("src/test/resources/apache.crt")) {
            bstCert = (X509Certificate) CertificateFactory.getInstance("X.509")
                    .generateCertificate(in);
        }

        assertFalse("the test needs two distinct identities",
                signerCert.getSubjectX500Principal().equals(bstCert.getSubjectX500Principal()));
    }

    private static WSSecurityEngineResult signatureResult(X509Certificate cert) {
        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.SIGN);
        result.put(WSSecurityEngineResult.TAG_PRINCIPAL, cert.getSubjectX500Principal());
        result.put(WSSecurityEngineResult.TAG_X509_CERTIFICATE, cert);
        return result;
    }

    private static WSSecurityEngineResult bstResult(X509Certificate cert) {
        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.BST);
        result.put(WSSecurityEngineResult.TAG_X509_CERTIFICATES, new X509Certificate[] {cert});
        return result;
    }

    private static MessageContext requestWith(WSSecurityEngineResult... results)
            throws Exception {
        List<WSSecurityEngineResult> engineResults = new ArrayList<WSSecurityEngineResult>();
        Collections.addAll(engineResults, results);
        List<WSHandlerResult> handlerResults = new ArrayList<WSHandlerResult>();
        handlerResults.add(new WSHandlerResult(null, engineResults,
                Collections.<Integer, List<WSSecurityEngineResult>>emptyMap()));

        SOAPEnvelope envelope = OMAbstractFactory.getSOAP11Factory().getDefaultEnvelope();
        envelope.getBody().addChild(AXIOMUtil.stringToOM(RST));

        MessageContext msgCtx = new MessageContext();
        msgCtx.setEnvelope(envelope);
        msgCtx.setProperty(WSHandlerConstants.RECV_RESULTS, handlerResults);
        return msgCtx;
    }

    /** A BST alone establishes no identity, so the request must be refused. */
    public void testBareBstDoesNotAuthenticate() throws Exception {
        try {
            RahasData data = new RahasData(requestWith(bstResult(bstCert)));
            fail("a bare BST must not yield a principal, but got " + data.getPrincipal());
        } catch (TrustException expected) {
            // no verified principal and no SAML assertion: REQUEST_FAILED
        }
    }

    /**
     * Results are walked in the order the elements appear in the message, which the
     * sender controls. A BST placed after a verified signature must not replace the
     * identity or the proof-key certificate that the signature established.
     */
    public void testBstAfterSignatureDoesNotOverrideIdentity() throws Exception {
        RahasData data = new RahasData(
                requestWith(signatureResult(signerCert), bstResult(bstCert)));

        assertEquals(signerCert.getSubjectX500Principal(), data.getPrincipal());
        assertSame(signerCert, data.getClientCert());
    }

    /** Control: a verified signature alone still authenticates the requestor. */
    public void testSignatureEstablishesIdentity() throws Exception {
        RahasData data = new RahasData(requestWith(signatureResult(signerCert)));

        assertEquals(signerCert.getSubjectX500Principal(), data.getPrincipal());
        assertSame(signerCert, data.getClientCert());
    }
}
