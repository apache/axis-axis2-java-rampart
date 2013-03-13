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
import org.apache.ws.security.handler.WSHandlerConstants;

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
}
