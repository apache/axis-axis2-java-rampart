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

import javax.xml.namespace.QName;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;

/**
 * RAMPART-419: an outgoing envelope without a soap:Header (a message built by hand,
 * or one that never passed through addressing) made WSS4J create the header as a
 * plain DOM element, which the Axiom DOM envelope refuses.
 */
public class HeaderlessEnvelopeTest extends MessageBuilderTestBase {

    private static final String POLICY = "test-resources/policy/rampart-asymm-binding-1.xml";

    public void testSoap11EnvelopeWithoutHeader() throws Exception {
        buildWithoutHeader(getMsgCtx());
    }

    public void testSoap12EnvelopeWithoutHeader() throws Exception {
        buildWithoutHeader(getMsgCtx12());
    }

    private void buildWithoutHeader(MessageContext ctx) throws Exception {
        SOAPEnvelope env = ctx.getEnvelope();
        env.getHeader().detach();
        assertNull("test setup: the envelope must have no header", env.getHeader());

        Policy policy = loadPolicy(POLICY);
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        new MessageBuilder().build(ctx);

        SOAPHeader header = ctx.getEnvelope().getHeader();
        assertNotNull("a soap:Header must have been created", header);
        assertEquals("the created header must be the envelope's first child",
                header, ctx.getEnvelope().getFirstElement());

        ArrayList<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
}
