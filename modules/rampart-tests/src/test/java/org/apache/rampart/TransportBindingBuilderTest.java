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

import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.derivedKey.ConversationConstants;

import javax.xml.namespace.QName;
import java.util.ArrayList;
import java.util.List;

public class TransportBindingBuilderTest extends MessageBuilderTestBase {

    public void testTransportBinding() throws Exception {
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-transport-binding.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        List<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testTransportBindingAbsentSignedHeader() throws Exception {
        // RAMPART-431: the policy lists a WS-Addressing 2005/08 "To" header in the
        // endorsing token's SignedParts, but the message does not contain that header.
        // The build must succeed (the absent header is skipped) rather than fail with
        // "Element to encrypt/sign not found: http://www.w3.org/2005/08/addressing, To".
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-transport-binding-absent-signed-header.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        List<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testTransportBindingNoBST() throws Exception {
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-transport-binding-no-bst.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        List<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testTransportBindingWithDK() throws Exception {
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-transport-binding-dk.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        List<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.USERNAME_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12,
                           ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testTransportBindingWithDKServerSide() throws Exception {
        MessageContext ctx = getMsgCtx();
        ctx.setServerSide(true);

        String policyXml = "test-resources/policy/rampart-transport-binding-dk.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        List<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }


}
