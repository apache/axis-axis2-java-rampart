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

package org.apache.rampart;

import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.rahas.Token;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.dom.WSConstants;

/**
 * RAMPART-362: a message protected with an issued SAML token references the
 * assertion from ds:KeyInfo with a wsse:KeyIdentifier, as the SAML Token Profile
 * requires, and not with a wsse:Reference URI. The URI form is a local reference
 * that a recipient cannot resolve when the assertion is not in the message.
 */
public class IssuedTokenReferenceTest extends MessageBuilderTestBase {

    private static final String SAML1_NS = "urn:oasis:names:tc:SAML:1.0:assertion";
    private static final String SAML2_NS = "urn:oasis:names:tc:SAML:2.0:assertion";
    private static final QName STR = new QName(WSConstants.WSSE_NS, "SecurityTokenReference");
    private static final QName KEY_IDENTIFIER = new QName(WSConstants.WSSE_NS, "KeyIdentifier");
    private static final QName REFERENCE = new QName(WSConstants.WSSE_NS, "Reference");
    private static final QName TOKEN_TYPE = new QName(WSConstants.WSSE11_NS, "TokenType");

    /** A stand-in for an issued holder-of-key assertion: only its id and namespace matter here. */
    private static OMElement assertion(String ns, String idAttribute, String id) {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace saml = fac.createOMNamespace(ns, "saml");
        OMElement assertion = fac.createOMElement("Assertion", saml);
        assertion.addAttribute(idAttribute, id, null);
        return assertion;
    }

    private SOAPEnvelope build(OMElement assertion, String id) throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy("test-resources/policy/rampart-symm-binding-issued-token.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        Token token = new Token(id, assertion, new Date(),
                new Date(System.currentTimeMillis() + 300000));
        token.setSecret(new byte[16]);
        TrustUtil.getTokenStore(ctx).add(token);
        // The token is already issued: no STS round trip
        ctx.setProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN, id);

        new MessageBuilder().build(ctx);

        List<QName> expected = new ArrayList<QName>();
        expected.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        expected.add(assertion.getQName());
        expected.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        expected.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        verifySecHeader(expected.iterator(), ctx.getEnvelope());
        return ctx.getEnvelope();
    }

    private static OMElement securityHeader(SOAPEnvelope env) {
        return env.getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
    }

    private static OMElement keyInfoStr(OMElement parent) {
        OMElement keyInfo = parent.getFirstChildWithName(
                new QName(WSConstants.SIG_NS, WSConstants.KEYINFO_LN));
        assertNotNull("ds:KeyInfo missing under " + parent.getQName(), keyInfo);
        OMElement str = keyInfo.getFirstChildWithName(STR);
        assertNotNull("wsse:SecurityTokenReference missing under " + parent.getQName(), str);
        return str;
    }

    private static void assertSamlKeyIdentifier(OMElement str, String valueType,
                                                String tokenType, String id) {
        assertNull("the assertion must not be referenced by URI", str.getFirstChildWithName(REFERENCE));
        OMElement ki = str.getFirstChildWithName(KEY_IDENTIFIER);
        assertNotNull("wsse:KeyIdentifier missing", ki);
        assertEquals(valueType, ki.getAttributeValue(new QName("ValueType")));
        assertEquals(id, ki.getText());
        assertEquals(tokenType, str.getAttributeValue(TOKEN_TYPE));
    }

    private static void assertReferences(SOAPEnvelope env, String valueType, String tokenType,
                                         String id) {
        OMElement secHeader = securityHeader(env);
        OMElement signature = secHeader.getFirstChildWithName(
                new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        assertSamlKeyIdentifier(keyInfoStr(signature), valueType, tokenType, id);

        Iterator<OMElement> bodyChildren = env.getBody().getChildElements();
        assertTrue("body must be encrypted", bodyChildren.hasNext());
        OMElement encryptedData = bodyChildren.next();
        assertEquals(new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN), encryptedData.getQName());
        assertSamlKeyIdentifier(keyInfoStr(encryptedData), valueType, tokenType, id);
    }

    public void testSaml11AssertionReferencedByKeyIdentifier() throws Exception {
        String id = "_saml1-assertion-id";
        SOAPEnvelope env = build(assertion(SAML1_NS, "AssertionID", id), id);
        assertReferences(env, WSConstants.WSS_SAML_KI_VALUE_TYPE, WSConstants.WSS_SAML_TOKEN_TYPE, id);
    }

    public void testSaml20AssertionReferencedByKeyIdentifier() throws Exception {
        String id = "_saml2-assertion-id";
        SOAPEnvelope env = build(assertion(SAML2_NS, "ID", id), id);
        assertReferences(env, WSConstants.WSS_SAML2_KI_VALUE_TYPE, WSConstants.WSS_SAML2_TOKEN_TYPE, id);
    }
}
