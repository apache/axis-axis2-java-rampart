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

import java.io.ByteArrayInputStream;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rampart.policy.RampartPolicyBuilder;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.model.AbstractSecurityAssertion;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.apache.ws.secpolicy.model.UsernameToken;
import org.apache.ws.secpolicy.model.X509Token;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

/**
 * RAMPART-286: wsp:Optional on IncludeTimestamp, UsernameToken, SignedParts,
 * EncryptedParts and a supporting X509Token must reach the policy model, a client
 * with no user configured must leave an optional UsernameToken out, and a service
 * must accept the request that arrives without it.
 */
public class OptionalAssertionsTest extends MessageBuilderTestBase {

    private static final String SP12_NS = "http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702";

    private RampartPolicyData build(String policyXml) throws Exception {
        Policy policy = loadPolicy(policyXml);
        List<Assertion> alternative = policy.getAlternatives().next();
        return RampartPolicyBuilder.build(alternative);
    }

    private static Token onlyToken(SupportingToken group) {
        assertNotNull("supporting token group missing", group);
        assertEquals(1, group.getTokens().size());
        return group.getTokens().get(0);
    }

    private void assertOptionalFlagsParsed(RampartPolicyData rpd) {
        assertTrue(rpd.isIncludeTimestamp());
        assertTrue("IncludeTimestamp wsp:Optional lost", rpd.isIncludeTimestampOptional());
        assertTrue(rpd.isSignBody());
        assertTrue("SignedParts wsp:Optional lost", rpd.isSignBodyOptional());
        assertTrue(rpd.isEncryptBody());
        assertTrue("EncryptedParts wsp:Optional lost", rpd.isEncryptBodyOptional());

        Token ut = onlyToken(rpd.getSignedSupportingTokens());
        assertTrue(ut instanceof UsernameToken);
        assertTrue("UsernameToken wsp:Optional lost", ut.isOptional());

        assertEquals(1, rpd.getSupportingTokensList().size());
        Token x509 = onlyToken(rpd.getSupportingTokensList().get(0));
        assertTrue(x509 instanceof X509Token);
        assertTrue("X509Token wsp:Optional lost", x509.isOptional());
    }

    public void testOptionalFlagsReachThePolicyDataForSecurityPolicy12() throws Exception {
        assertOptionalFlagsParsed(build("test-resources/policy/rampart-optional-assertions-sp12.xml"));
    }

    public void testOptionalFlagsReachThePolicyDataForSecurityPolicy11() throws Exception {
        assertOptionalFlagsParsed(build("test-resources/policy/rampart-optional-assertions-sp11.xml"));
    }

    /** The attribute is read whichever WS-Policy namespace the document uses. */
    public void testOptionalAttributeIsReadInAnyWsPolicyNamespace() throws Exception {
        assertTrue(AbstractSecurityAssertion.readOptionalAttribute(element(
                "http://schemas.xmlsoap.org/ws/2004/09/policy", "true")));
        assertTrue(AbstractSecurityAssertion.readOptionalAttribute(element(
                "http://www.w3.org/ns/ws-policy", "true")));
        assertTrue(AbstractSecurityAssertion.readOptionalAttribute(element(
                "http://www.w3.org/ns/ws-policy", "1")));
        assertFalse(AbstractSecurityAssertion.readOptionalAttribute(element(
                "http://schemas.xmlsoap.org/ws/2004/09/policy", "false")));
        assertFalse(AbstractSecurityAssertion.readOptionalAttribute(AXIOMUtil.stringToOM(
                "<sp:UsernameToken xmlns:sp='" + SP12_NS + "'/>")));
    }

    private static OMElement element(String wspNs, String value) throws Exception {
        return AXIOMUtil.stringToOM("<sp:UsernameToken xmlns:sp='" + SP12_NS
                + "' xmlns:wsp='" + wspNs + "' wsp:Optional='" + value + "'/>");
    }

    /** No user configured: the optional token is left out and the service accepts. */
    public void testOptionalUsernameTokenIsSkippedWithoutAUserAndAccepted() throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy("test-resources/policy/rampart-optional-username-token.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        new MessageBuilder().build(ctx);
        assertFalse("client must not send a UsernameToken it has no user for",
                hasUsernameToken(ctx.getEnvelope()));

        processAsService(ctx, policy);
    }

    /** With a user configured the optional token is sent and validated as before. */
    public void testOptionalUsernameTokenIsSentWithAUser() throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy("test-resources/policy/rampart-optional-username-token.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        ctx.getOptions().setUserName("Ron");
        ctx.getOptions().setPassword("noR");

        new MessageBuilder().build(ctx);
        assertTrue(hasUsernameToken(ctx.getEnvelope()));

        processAsService(ctx, policy);
    }

    /** A foreign client may send no security header at all; all-optional means that is fine. */
    public void testRequestWithNoSecurityHeaderIsAcceptedWhenAllAssertionsAreOptional() throws Exception {
        MessageContext ctx = getMsgCtx();
        assertFalse(hasSecurityHeader(ctx.getEnvelope()));
        processAsService(ctx, loadPolicy("test-resources/policy/rampart-optional-username-token.xml"));
    }

    /** ...but a required token still makes the missing header a fault. */
    public void testRequestWithNoSecurityHeaderIsStillRefusedForARequiredToken() throws Exception {
        MessageContext ctx = getMsgCtx();
        try {
            processAsService(ctx, loadPolicy("test-resources/policy/rampart-plaintext-password.xml"));
            fail("a required UsernameToken needs a security header");
        } catch (RampartException expected) {
            // missingSecurityHeader
        }
    }

    private static boolean hasSecurityHeader(SOAPEnvelope env) {
        return env.getHeader() != null && env.getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN)) != null;
    }

    /** A required token with no user is still an error, as it always was. */
    public void testRequiredUsernameTokenWithoutAUserStillFails() throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY,
                loadPolicy("test-resources/policy/rampart-plaintext-password.xml"));
        try {
            new MessageBuilder().build(ctx);
            fail("a required UsernameToken needs a user");
        } catch (RampartException expected) {
            // userMissing
        }
    }

    private static final String WSP_NS = "http://schemas.xmlsoap.org/ws/2004/09/policy";

    /** A transport binding whose only requirement is a timestamp, optional or not. */
    private static Policy transportTimestampPolicy(boolean optional) throws Exception {
        String xml = "<wsp:Policy xmlns:wsp='" + WSP_NS + "' xmlns:sp='" + SP12_NS + "'>"
                + "<wsp:ExactlyOne><wsp:All><sp:TransportBinding><wsp:Policy>"
                + "<sp:TransportToken><wsp:Policy/></sp:TransportToken>"
                + "<sp:AlgorithmSuite><wsp:Policy><sp:Basic128/></wsp:Policy></sp:AlgorithmSuite>"
                + "<sp:Layout><wsp:Policy><sp:Lax/></wsp:Policy></sp:Layout>"
                + "<sp:IncludeTimestamp" + (optional ? " wsp:Optional='true'" : "") + "/>"
                + "</wsp:Policy></sp:TransportBinding></wsp:All></wsp:ExactlyOne></wsp:Policy>";
        return PolicyEngine.getPolicy(AXIOMUtil.stringToOM(xml));
    }

    private static RampartPolicyData build(Policy policy) throws Exception {
        return RampartPolicyBuilder.build(policy.getAlternatives().next());
    }

    /** Only the asymmetric builder used to carry the flag through. */
    public void testSymmetricAndTransportBindingsCarryTheOptionalTimestampFlag() throws Exception {
        RampartPolicyData symmetric = build("test-resources/policy/rampart-optional-timestamp-symm.xml");
        assertTrue(symmetric.isIncludeTimestamp());
        assertTrue("symmetric binding lost IncludeTimestamp wsp:Optional",
                symmetric.isIncludeTimestampOptional());

        RampartPolicyData transport = build(transportTimestampPolicy(true));
        assertTrue(transport.isIncludeTimestamp());
        assertTrue("transport binding lost IncludeTimestamp wsp:Optional",
                transport.isIncludeTimestampOptional());
        assertFalse(build(transportTimestampPolicy(false)).isIncludeTimestampOptional());
    }

    /** The client always sends a timestamp; a peer that does not is fine only when optional. */
    public void testAMissingTimestampIsAcceptedOnlyWhenOptional() throws Exception {
        processWithoutTimestamp(transportTimestampPolicy(true));
        try {
            processWithoutTimestamp(transportTimestampPolicy(false));
            fail("a required timestamp must be missed");
        } catch (RampartException expected) {
            // timestampMissing
        }
    }

    private void processWithoutTimestamp(Policy policy) throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        new MessageBuilder().build(ctx);
        OMElement timestamp = securityHeader(ctx.getEnvelope()).getFirstChildWithName(
                new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        assertNotNull("the client still sends a timestamp", timestamp);
        timestamp.detach();
        processAsService(ctx, policy);
    }

    /** Optional body parts: the client leaves the body alone and the service accepts it. */
    public void testOptionalBodyPartsAreNeitherSignedNorEncryptedAndStillAccepted() throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy("test-resources/policy/rampart-optional-parts-asymm.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        new MessageBuilder().build(ctx);

        OMElement body = ctx.getEnvelope().getBody();
        assertNull("optional EncryptedParts: body must stay in the clear",
                body.getFirstChildWithName(new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN)));
        assertNull("optional SignedParts: body must not be referenced by the signature",
                body.getAttributeValue(new QName(WSConstants.WSU_NS, "Id")));
        assertNotNull("the binding itself still signs the timestamp",
                securityHeader(ctx.getEnvelope()).getFirstChildWithName(
                        new QName(WSConstants.SIG_NS, WSConstants.SIG_LN)));

        processAsService(ctx, policy);
    }

    /** The engine's header-less acceptance rests on this distinction. */
    public void testAnAllOptionalPolicyRequiresNoSecurityHeaderUnlessOptionalCounts() throws Exception {
        RampartPolicyData allOptional = build("test-resources/policy/rampart-optional-assertions-sp12.xml");
        assertTrue(RampartUtil.isSecHeaderRequired(allOptional, false, true));
        assertFalse(RampartUtil.isSecHeaderRequired(allOptional, false, true, false));

        RampartPolicyData required = build("test-resources/policy/rampart-asymm-binding-1.xml");
        assertTrue(RampartUtil.isSecHeaderRequired(required, false, true, false));
    }

    private static OMElement securityHeader(SOAPEnvelope env) {
        assertNotNull(env.getHeader());
        OMElement security = env.getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
        assertNotNull("no security header was built", security);
        return security;
    }

    private static boolean hasUsernameToken(SOAPEnvelope env) {
        if (env.getHeader() == null) {
            return false;
        }
        OMElement security = env.getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
        return security != null && security.getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN)) != null;
    }

    /** Re-parses the built envelope and runs it through the engine as the service. */
    private static void processAsService(MessageContext ctx, Policy policy) throws Exception {
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream in = new ByteArrayInputStream(env.toString().getBytes("UTF-8"));
        env = (SOAPEnvelope) new SOAPBuilder().processDocument(in, "text/xml", ctx);
        ctx.setEnvelope(env);

        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();
        Parameter clientSide = axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE);
        if (clientSide != null) {
            axisService.removeParameter(clientSide);
        }
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        ctx.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new TestCBHandler());

        new RampartEngine().process(ctx);
    }
}
