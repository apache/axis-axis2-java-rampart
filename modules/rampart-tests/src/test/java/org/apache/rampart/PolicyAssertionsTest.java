/* 
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 * 
 * http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rampart;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.neethi.Policy;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

import java.io.ByteArrayInputStream;

public class PolicyAssertionsTest extends MessageBuilderTestBase {

    public PolicyAssertionsTest(String name) {
        super(name);
    }

    public void testRequiredElementsValid() throws Exception {

        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-asymm-required-elements.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, "text/xml", ctx);
        ctx.setEnvelope(env);

        RampartEngine engine = new RampartEngine();
        engine.process(ctx);

    }

    public void testRequiredElementsInvalid() throws Exception {

        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-asymm-required-elements-2.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, "text/xml", ctx);
        ctx.setEnvelope(env);

        RampartEngine engine = new RampartEngine();

        try {
            engine.process(ctx);
            fail(" This should have thrown RampartException: " +
                    "Required Elements not found in the incoming message : wsrm:Sequence");
        } catch (RampartException expected) {
            // Ignore intentionally as the test is supposed to throw an exception
        }

    }

    public void testHashedPasswordRequiredValid() throws Exception {

        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-hashed-password.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        ctx.getOptions().setUserName( "Ron" );
        ctx.getOptions().setPassword( "noR" );
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, "text/xml", ctx);
        ctx.setEnvelope(env);

        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();            
        axisService.removeParameter(axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE));

        ctx.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new TestCBHandler());

        RampartEngine engine = new RampartEngine();
        engine.process(ctx);

    }

    public void testHashedPasswordRequiredInvalid() throws Exception {

        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-plaintext-password.xml";
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        ctx.getOptions().setUserName( "Ron" );
        ctx.getOptions().setPassword( "noR" );
        
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, "text/xml", ctx);
        ctx.setEnvelope(env);

        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();            
        axisService.removeParameter(axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE));

        policyXml = "test-resources/policy/rampart-hashed-password.xml";
        policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        ctx.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new TestCBHandler());

        RampartEngine engine = new RampartEngine();

        try {
            engine.process(ctx);
            fail(" This should have thrown RampartException: Invalid UsernameToken Type.");
        } catch (RampartException expected) {
            // Ignore intentionally as the test is supposed to throw an exception
        }

    }

    public void testAlgorithmSuiteDowngradeRejected() throws Exception {
        // RAMPART-44 / RAMPART-252: a message signed with a weaker algorithm suite
        // (Basic128, SHA-1) must be rejected when the service policy requires a stronger
        // suite (Basic128Sha256, SHA-256), so a peer cannot downgrade the digest
        // algorithm. Without algorithm-suite enforcement the SHA-1 signature would verify
        // and the message would be accepted.
        MessageContext ctx = getMsgCtx();

        // Build the request with the SHA-1 (Basic128) policy.
        Policy buildPolicy = loadPolicy("test-resources/policy/rampart-asymm-binding-1.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, buildPolicy);
        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, "text/xml", ctx);
        ctx.setEnvelope(env);

        // Validate as the server with the SHA-256 (Basic128Sha256) policy.
        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();
        axisService.removeParameter(axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE));

        Policy verifyPolicy = loadPolicy("test-resources/policy/rampart-asymm-binding-1-sha256.xml");
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, verifyPolicy);

        RampartEngine engine = new RampartEngine();
        try {
            engine.process(ctx);
            fail("A message signed with SHA-1 must be rejected when the policy requires SHA-256");
        } catch (Exception expected) {
            // Expected: algorithm-suite enforcement rejects the weaker digest algorithm.
        }
    }
}
