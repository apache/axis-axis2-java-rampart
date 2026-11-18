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

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

import javax.xml.namespace.QName;
import java.io.ByteArrayInputStream;
import java.util.List;

/**
 * RAMPART-289: a request built with sp:EncryptBeforeSigning must validate when the
 * encryption covers a supporting token or the signature as well as the body.
 * Each policy is built as the client and then processed as the service.
 */
public class EncryptBeforeSigningSupportingTokensTest extends MessageBuilderTestBase {

    public void testAsymmetricEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-ebs-encr-sup-tokens.xml");
    }

    public void testAsymmetricSignedEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-ebs-signed-encr-sup-tokens.xml");
    }

    public void testSymmetricEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-symm-binding-ebs-encr-sup-tokens.xml");
    }

    public void testAsymmetricEncryptedSignature() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-ebs-encr-sig.xml");
    }

    public void testAsymmetricSignBeforeEncryptEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-sbe-encr-sup-tokens.xml");
    }

    public void testAsymmetricSignBeforeEncryptSignedEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-sbe-signed-encr-sup-tokens.xml");
    }

    public void testSymmetricSignBeforeEncryptEncryptedSupportingToken() throws Exception {
        roundTrip("test-resources/policy/rampart-symm-binding-sbe-encr-sup-tokens.xml");
    }

    /** A password-less token (sp:NoPassword) is reported by WSS4J under its own action. */
    public void testEncryptedSupportingTokenWithoutPassword() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-ebs-encr-sup-tokens-nopassword.xml");
    }

    /** A token the policy wants encrypted but which arrives in the clear must be refused. */
    public void testClearTextSupportingTokenIsRefusedWhenEncryptionIsRequired() throws Exception {
        assertRefused("test-resources/policy/rampart-asymm-binding-ebs-plain-sup-tokens.xml",
                "test-resources/policy/rampart-asymm-binding-ebs-encr-sup-tokens.xml");
    }

    /** The signature covers nothing but the signed-encrypted token; that is not an unexpected signature. */
    public void testSignatureOverTheSignedEncryptedTokenAlone() throws Exception {
        roundTrip("test-resources/policy/rampart-asymm-binding-signed-encr-sup-token-only.xml");
    }

    /** A request without the encrypted supporting token must still be refused. */
    public void testMissingEncryptedSupportingTokenIsRefused() throws Exception {
        assertRefused("test-resources/policy/rampart-asymm-binding-ebs.xml",
                "test-resources/policy/rampart-asymm-binding-ebs-encr-sup-tokens.xml");
    }

    public void testMissingSignedEncryptedSupportingTokenIsRefused() throws Exception {
        assertRefused("test-resources/policy/rampart-asymm-binding-ebs.xml",
                "test-resources/policy/rampart-asymm-binding-ebs-signed-encr-sup-tokens.xml");
    }

    private void assertRefused(String clientPolicyPath, String servicePolicyPath) throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy(clientPolicyPath));
        new MessageBuilder().build(ctx);
        try {
            processAsService(ctx, loadPolicy(servicePolicyPath));
            fail("the request has no supporting token and must be refused");
        } catch (RampartException expected) {
            // usernameTokenMissing
        }
    }

    private void roundTrip(String policyPath) throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy(policyPath);
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        new MessageBuilder().build(ctx);
        assertFalse("the supporting token must not be sent in the clear",
                hasClearTextUsernameToken(ctx.getEnvelope()));

        List<WSSecurityEngineResult> results = processAsService(ctx, policy);

        boolean signed = false;
        boolean encrypted = false;
        for (WSSecurityEngineResult result : results) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            signed |= action == WSConstants.SIGN;
            encrypted |= action == WSConstants.ENCR;
        }
        assertTrue("signature not processed", signed);
        assertTrue("encryption not processed", encrypted);
    }

    private static boolean hasClearTextUsernameToken(SOAPEnvelope env) {
        OMElement security = env.getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
        return security.getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN)) != null;
    }

    /** Re-parses the built envelope and runs it through the engine as the service. */
    private static List<WSSecurityEngineResult> processAsService(MessageContext ctx, Policy policy)
            throws Exception {
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

        return new RampartEngine().process(ctx);
    }
}
