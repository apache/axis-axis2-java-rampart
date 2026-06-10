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

public class AsymmetricBindingBuilderTest extends MessageBuilderTestBase {
    
    public void testAsymmBinding() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-1.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
    public void testAsymmBindingProtectTokens() throws Exception {
        // RAMPART-411: with sp:ProtectTokens the BinarySecurityToken must be signed.
        // The original failure was during signing ("Element to encrypt/sign not found:
        // ...BinarySecurityToken"), so a successful build that produces a BST and a
        // Signature proves the token is now correctly added to the signature (by its
        // wsu:Id) and signed.
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-asymm-binding-protecttokens.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        ArrayList<QName> list = new ArrayList<QName>();
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));

        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testAsymmBindingServerSide() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        ctx.setServerSide(true);
        String policyXml = "test-resources/policy/rampart-asymm-binding-1.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));

        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
    public void testAsymmBindingWithSigDK() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-2-sig-dk.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));

        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
    public void testAsymmBindingWithDK() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-3-dk.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
    public void testAsymmBindingWithDKEncrBeforeSig() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-4-dk-ebs.xml";
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
    
    
    public void testAsymmBindingEncrBeforeSig() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-5-ebs.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
         
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
    public void testAsymmBindingTripleDesRSA15() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(WSConstants.WSSE_NS, WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }

    public void testAsymmBindingTripleDesRSA15DK() throws Exception {
        MessageContext ctx = getMsgCtx();
        
        String policyXml = "test-resources/policy/rampart-asymm-binding-7-3des-r15-DK.xml";
        Policy policy = this.loadPolicy(policyXml);
        
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);
        
        ArrayList<QName> list = new ArrayList<QName>();
        
        list.add(new QName(WSConstants.WSU_NS, WSConstants.TIMESTAMP_TOKEN_LN));
        list.add(new QName(WSConstants.WSSE_NS,WSConstants.BINARY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.ENC_KEY_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.ENC_NS, WSConstants.REF_LIST_LN));
        list.add(new QName(ConversationConstants.WSC_NS_05_12, ConversationConstants.DERIVED_KEY_TOKEN_LN));
        list.add(new QName(WSConstants.SIG_NS, WSConstants.SIG_LN));
        
        this.verifySecHeader(list.iterator(), ctx.getEnvelope());
    }
    
}
