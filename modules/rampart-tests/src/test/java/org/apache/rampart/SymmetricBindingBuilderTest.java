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

import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.derivedKey.ConversationConstants;

public class SymmetricBindingBuilderTest extends MessageBuilderTestBase {
	
	public void testSymmBinding() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-symm-binding-1.xml";

        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
	}
	
//	public void testSymmBindingServerSide() {
//		
//        try {
//            MessageContext ctx = getMsgCtx();
//            
//            ctx.setServerSide(true);
//            String policyXml = "test-resources/policy/rampart-symm-binding-1.xml";
//            Policy policy = this.loadPolicy(policyXml);
//            
//            ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
//            
//            MessageBuilder builder = new MessageBuilder();
//            builder.build(ctx);
//            
//            ArrayList list = new ArrayList();
//            
//            list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
//            list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
//            
//            this.verifySecHeader(list.iterator(), ctx.getEnvelope());
//            
//        } catch(Exception e) {
//            e.printStackTrace();
//            fail(e.getMessage());
//        }
//	}
	
	public void testSymmBindingWithDK() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-symm-binding-2-dk.xml";

        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
	}
	
	public void testSymmBindingWithDKEncrSig() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-symm-binding-3-dk-es.xml";

        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
	}
	
	public void testSymmBindingEncrBeforeSig() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-symm-binding-4-ebs.xml";

        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
	}
	
	public void testSymmBindingWithDKEncrBeforeSig() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-symm-binding-5-dk-ebs.xml";

        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));

        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
	}

}
