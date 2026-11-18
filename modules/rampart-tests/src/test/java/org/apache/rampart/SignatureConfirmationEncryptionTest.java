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
import java.util.Arrays;
import java.util.Collections;
import java.util.HashMap;
import java.util.Iterator;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;

/**
 * RAMPART-330: WS-SecurityPolicy 6.4 [Signature Protection]. When sp:EncryptSignature
 * is set, the wsse11:SignatureConfirmation elements of a response must be encrypted
 * along with the primary signature; when it is not set, they must stay in the clear.
 */
public class SignatureConfirmationEncryptionTest extends MessageBuilderTestBase {

    private static final QName SIG_CONF =
            new QName(WSConstants.WSSE11_NS, WSConstants.SIGNATURE_CONFIRMATION_LN);
    private static final QName ENC_DATA = new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN);

    /** The inbound results of a request that carried two signatures and an EncryptedKey. */
    private static List<WSHandlerResult> receivedResults(boolean withEncryptedKey) {
        List<WSSecurityEngineResult> results = new ArrayList<WSSecurityEngineResult>();
        Map<Integer, List<WSSecurityEngineResult>> actions =
                new HashMap<Integer, List<WSSecurityEngineResult>>();

        List<WSSecurityEngineResult> signatures = new ArrayList<WSSecurityEngineResult>();
        for (int i = 1; i <= 2; i++) {
            WSSecurityEngineResult sig = new WSSecurityEngineResult(WSConstants.SIGN);
            byte[] value = new byte[20];
            Arrays.fill(value, (byte) i);
            sig.put(WSSecurityEngineResult.TAG_SIGNATURE_VALUE, value);
            signatures.add(sig);
        }
        results.addAll(signatures);
        actions.put(WSConstants.SIGN, signatures);

        if (withEncryptedKey) {
            byte[] secret = new byte[16];
            WSSecurityEngineResult encr = new WSSecurityEngineResult(WSConstants.ENCR);
            encr.put(WSSecurityEngineResult.TAG_ID, "_ek");
            encr.put(WSSecurityEngineResult.TAG_SECRET, secret);
            encr.put(WSSecurityEngineResult.TAG_ENCRYPTED_EPHEMERAL_KEY, secret);
            results.add(encr);
            actions.put(WSConstants.ENCR, Collections.singletonList(encr));
        }
        return Collections.singletonList(new WSHandlerResult("", results, actions));
    }

    private OMElement buildResponse(String policyPath, boolean withEncryptedKey) throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();
        Parameter clientSide = axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE);
        if (clientSide != null) {
            axisService.removeParameter(clientSide);
        }
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy(policyPath));
        ctx.setProperty(WSHandlerConstants.RECV_RESULTS, receivedResults(withEncryptedKey));

        new MessageBuilder().build(ctx);

        return ctx.getEnvelope().getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
    }

    private static int count(OMElement parent, QName name) {
        int n = 0;
        for (Iterator<OMElement> it = parent.getChildrenWithName(name); it.hasNext(); it.next()) {
            n++;
        }
        return n;
    }

    private static void assertConfirmationsEncrypted(OMElement secHeader) {
        assertEquals("SignatureConfirmation must not be left in the clear",
                0, count(secHeader, SIG_CONF));
        assertEquals("the Signature must be encrypted",
                0, count(secHeader, new QName(WSConstants.SIG_NS, WSConstants.SIG_LN)));
        assertEquals("expected EncryptedData for the Signature and both confirmations",
                3, count(secHeader, ENC_DATA));
    }

    public void testAsymmetricBindingEncryptsSignatureConfirmations() throws Exception {
        assertConfirmationsEncrypted(
                buildResponse("test-resources/policy/rampart-asymm-binding-sigconf-es.xml", false));
    }

    public void testEncryptBeforeSigningEncryptsSignatureConfirmations() throws Exception {
        assertConfirmationsEncrypted(
                buildResponse("test-resources/policy/rampart-asymm-binding-sigconf-es-ebs.xml", false));
    }

    public void testSymmetricBindingEncryptsSignatureConfirmations() throws Exception {
        assertConfirmationsEncrypted(
                buildResponse("test-resources/policy/rampart-symm-binding-sigconf-es.xml", true));
    }

    public void testWithoutEncryptSignatureConfirmationsStayInTheClear() throws Exception {
        OMElement secHeader =
                buildResponse("test-resources/policy/rampart-asymm-binding-sigconf.xml", false);
        assertEquals(2, count(secHeader, SIG_CONF));
        assertEquals(1, count(secHeader, new QName(WSConstants.SIG_NS, WSConstants.SIG_LN)));
        assertEquals(0, count(secHeader, ENC_DATA));
    }
}
