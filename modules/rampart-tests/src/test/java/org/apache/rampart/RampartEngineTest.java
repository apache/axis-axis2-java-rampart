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

import java.io.ByteArrayInputStream;
import java.util.List;
import java.security.cert.X509Certificate;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

@RunWith(JUnit4.class)
public class RampartEngineTest extends MessageBuilderTestBase {
    /**
     * Tests that Rampart complains about missing security header in request.
     * 
     * @throws Exception
     */
    @Test(expected=RampartException.class)
    public void testEmptySOAPMessage() throws Exception {
        MessageContext ctx = getMsgCtx();

        String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
        Policy policy = this.loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        RampartEngine engine = new RampartEngine();
        engine.process(ctx);
    }

    @Test
    public void testValidSOAPMessage() throws Exception {
        runRampartEngine(getMsgCtx(), "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml");
    }

    @Test
    public void testValidSOAP12Message() throws Exception {
        runRampartEngine(getMsgCtx12(), "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml");
    }

    private void runRampartEngine(MessageContext ctx, String policyXml) throws Exception {
        Policy policy = loadPolicy(policyXml);

        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);

        MessageBuilder builder = new MessageBuilder();
        builder.build(ctx);

        // Building the SOAP envelope from the OMElement
        buildSOAPEnvelope(ctx);

        RampartEngine engine = new RampartEngine();
        List<org.apache.ws.security.WSSecurityEngineResult> results = engine.process(ctx);

        /*
        The principle purpose of the test case is to verify that the above processes
        without throwing an exception. However, perform a minimal amount of validation on the
        results.
        */
        assertNotNull("RampartEngine returned null result", results);
        //verify cert was stored
        X509Certificate usedCert = null;
        for (WSSecurityEngineResult result : results) {
            Integer action = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (action == WSConstants.SIGN) {
                //the result is for the signature, which contains the used certificate
                usedCert = (X509Certificate) result.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                break;
            }
        }
        assertNotNull("Result of processing did not include a certificate", usedCert);
    }

    private void buildSOAPEnvelope(MessageContext ctx) throws Exception {
        SOAPBuilder soapBuilder = new SOAPBuilder();
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream inStream = new ByteArrayInputStream(env.toString().getBytes());
        env = (SOAPEnvelope) soapBuilder.processDocument(inStream, env.getVersion().getMediaType().toString(), ctx);
        ctx.setEnvelope(env);
    }
}
