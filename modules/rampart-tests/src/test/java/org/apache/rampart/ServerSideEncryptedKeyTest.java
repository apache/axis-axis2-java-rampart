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
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.neethi.Policy;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;

/**
 * RAMPART-329: a service building a symmetric-binding response takes the session
 * key from the request's EncryptedKey and keeps it in the token store under the
 * EncryptedKey's Id. That Id is only unique within one SOAP message; some stacks
 * reuse "_1", "_2" on every call. The second call from such a client must not fail
 * with "Error in adding token into store", and each response must be built from
 * its own request's key.
 */
public class ServerSideEncryptedKeyTest extends MessageBuilderTestBase {

    private static final String REUSED_ID = "_5002";

    /** A fabricated inbound result: the EncryptedKey WSS4J would have decrypted. */
    private static List<WSHandlerResult> encryptedKeyResult(String id, byte[] secret) {
        WSSecurityEngineResult result = new WSSecurityEngineResult(WSConstants.ENCR);
        result.put(WSSecurityEngineResult.TAG_ID, id);
        result.put(WSSecurityEngineResult.TAG_SECRET, secret);
        result.put(WSSecurityEngineResult.TAG_ENCRYPTED_EPHEMERAL_KEY, secret);
        List<WSSecurityEngineResult> results = new ArrayList<WSSecurityEngineResult>();
        results.add(result);
        return Collections.singletonList(new WSHandlerResult("", results,
                Collections.singletonMap(WSConstants.ENCR, results)));
    }

    private static byte[] key(int seed) {
        byte[] key = new byte[16];
        Arrays.fill(key, (byte) seed);
        return key;
    }

    /** Builds the service's response for a request that carried the given EncryptedKey. */
    private MessageContext buildResponse(TokenStorage sharedStore, String encryptedKeyId,
                                         byte[] secret) throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();
        Parameter clientSide = axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE);
        if (clientSide != null) {
            axisService.removeParameter(clientSide);
        }
        if (sharedStore != null) {
            ctx.getConfigurationContext().setProperty(TokenStorage.TOKEN_STORAGE_KEY, sharedStore);
        }
        Policy policy = loadPolicy("test-resources/policy/rampart-symm-binding-1.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        ctx.setProperty(WSHandlerConstants.RECV_RESULTS, encryptedKeyResult(encryptedKeyId, secret));

        new MessageBuilder().build(ctx);

        List<QName> expected = new ArrayList<QName>();
        expected.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        expected.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        expected.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        verifySecHeader(expected.iterator(), ctx.getEnvelope());
        return ctx;
    }

    public void testASecondRequestReusingTheEncryptedKeyIdStillGetsAResponse() throws Exception {
        MessageContext first = buildResponse(null, REUSED_ID, key(1));
        TokenStorage store = TrustUtil.getTokenStore(first);

        // Same Id, different key, same service: this used to fail on the store add.
        buildResponse(store, REUSED_ID, key(2));

        assertTrue("the store must hold the latest key under the reused Id",
                Arrays.equals(key(2), store.getToken(REUSED_ID).getSecret()));
    }

    public void testDistinctIdsKeepBothKeys() throws Exception {
        MessageContext first = buildResponse(null, "_1", key(1));
        TokenStorage store = TrustUtil.getTokenStore(first);
        buildResponse(store, "_2", key(2));

        assertTrue(Arrays.equals(key(1), store.getToken("_1").getSecret()));
        assertTrue(Arrays.equals(key(2), store.getToken("_2").getSecret()));
    }
}
