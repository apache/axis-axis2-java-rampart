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
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.rahas.Token;
import org.apache.rahas.TrustUtil;
import org.apache.rampart.util.RampartUtil;
import org.apache.wss4j.dom.WSConstants;

/**
 * A transport binding endorsed by a SecureConversationToken without derived keys
 * references the wsc:SecurityContextToken from ds:KeyInfo with the SCT value type of
 * the conversation version in use. It used to carry the SAML 1.x assertion value type.
 */
public class TransportSecureConversationReferenceTest extends MessageBuilderTestBase {

    private static final String WSC_NS = "http://schemas.xmlsoap.org/ws/2005/02/sc";
    private static final String SCT_ID = "sct-1";

    @SuppressWarnings("unchecked")
    public void testEndorsingSctReferencedWithSctValueType() throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy("test-resources/policy/rampart-transport-binding-sct.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace wsc = fac.createOMNamespace(WSC_NS, "wsc");
        OMElement sct = fac.createOMElement("SecurityContextToken", wsc);
        sct.addAttribute("Id", SCT_ID, fac.createOMNamespace(WSConstants.WSU_NS, "wsu"));
        fac.createOMElement("Identifier", wsc, sct).setText("urn:uuid:sct-1");

        // An SCT obtained through an attached wsse:Reference is stored under "#" + wsu:Id
        Token token = new Token("#" + SCT_ID, sct, new Date(),
                new Date(System.currentTimeMillis() + 300000));
        token.setSecret(new byte[16]);
        token.setState(Token.ISSUED);
        TrustUtil.getTokenStore(ctx).add(token);
        RampartUtil.getContextMap(ctx).put(RampartUtil.getContextIdentifierKey(ctx), "#" + SCT_ID);

        new MessageBuilder().build(ctx);

        List<QName> expected = new ArrayList<QName>();
        expected.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        expected.add(sct.getQName());
        expected.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        verifySecHeader(expected.iterator(), ctx.getEnvelope());

        OMElement signature = ctx.getEnvelope().getHeader()
                .getFirstChildWithName(new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN))
                .getFirstChildWithName(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        OMElement reference = signature
                .getFirstChildWithName(new QName(WSConstants.SIG_NS, WSConstants.KEYINFO_LN))
                .getFirstChildWithName(new QName(WSConstants.WSSE_NS, "SecurityTokenReference"))
                .getFirstChildWithName(new QName(WSConstants.WSSE_NS, "Reference"));
        assertNotNull("wsse:Reference to the SCT missing", reference);
        assertEquals("#" + SCT_ID, reference.getAttributeValue(new QName("URI")));
        assertEquals(WSConstants.WSC_SCT, reference.getAttributeValue(new QName("ValueType")));
    }
}
