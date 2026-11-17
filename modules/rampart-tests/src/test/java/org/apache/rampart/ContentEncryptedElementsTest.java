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
import java.io.StringWriter;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.builder.SOAPBuilder;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rampart.policy.RampartPolicyBuilder;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.model.ContentEncryptedElements;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.WSHandlerConstants;

/**
 * RAMPART-421: sp:ContentEncryptedElements lost the namespace declarations of its
 * XPath expressions when serialized, and a policy whose only protection is content
 * encryption was treated as needing no security header at all, so the client sent
 * the message in the clear and the service refused it.
 */
public class ContentEncryptedElementsTest extends MessageBuilderTestBase {

    private static final String POLICY = "test-resources/policy/rampart-content-encrypted-only.xml";
    private static final String WSA_NS = "http://schemas.xmlsoap.org/ws/2004/08/addressing";

    private static ContentEncryptedElements contentEncryptedElements(Policy policy) {
        List<Assertion> alternative = policy.getAlternatives().next();
        for (Assertion assertion : alternative) {
            if (assertion instanceof ContentEncryptedElements) {
                return (ContentEncryptedElements) assertion;
            }
        }
        fail("no sp:ContentEncryptedElements in the policy");
        return null;
    }

    private static String serialize(Policy policy) throws Exception {
        StringWriter out = new StringWriter();
        XMLStreamWriter writer = XMLOutputFactory.newInstance().createXMLStreamWriter(out);
        policy.serialize(writer);
        writer.flush();
        return out.toString();
    }

    /** Serialize, parse again, and the XPath prefixes must still resolve. */
    public void testSerializedXPathKeepsItsNamespaceDeclarations() throws Exception {
        Policy original = loadPolicy(POLICY);
        assertEquals(WSA_NS, contentEncryptedElements(original).getDeclaredNamespaces().get("wsa"));

        String xml = serialize(original);
        assertTrue("sp:XPath must carry xmlns:wsa, was: " + xml,
                xml.contains("xmlns:wsa=\"" + WSA_NS + "\""));

        Policy reparsed = PolicyEngine.getPolicy(AXIOMUtil.stringToOM(xml));
        ContentEncryptedElements roundTripped = contentEncryptedElements(reparsed);
        assertEquals(2, roundTripped.getXPathExpressions().size());
        assertEquals(WSA_NS, roundTripped.getDeclaredNamespaces().get("wsa"));
    }

    /** Content encryption alone is a reason to build, and to expect, a security header. */
    public void testContentOnlyPolicyRequiresASecurityHeader() throws Exception {
        RampartPolicyData rpd = RampartPolicyBuilder.build(loadPolicy(POLICY).getAlternatives().next());
        assertEquals(2, rpd.getContentEncryptedElements().size());
        assertTrue("client must build a header", RampartUtil.isSecHeaderRequired(rpd, true, false));
        assertTrue("service must expect a header", RampartUtil.isSecHeaderRequired(rpd, false, true));
    }

    /** The client encrypts the header contents and the service decrypts and accepts them. */
    public void testHeaderContentIsEncryptedAndAcceptedEndToEnd() throws Exception {
        MessageContext ctx = getMsgCtx();
        Policy policy = loadPolicy(POLICY);
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        String originalTo = header(ctx.getEnvelope(), "To").getText();

        new MessageBuilder().build(ctx);

        OMElement security = ctx.getEnvelope().getHeader().getFirstChildWithName(
                new QName(WSConstants.WSSE_NS, WSConstants.WSSE_LN));
        assertNotNull("no security header was built", security);
        for (String name : new String[] {"To", "Action"}) {
            OMElement encrypted = header(ctx.getEnvelope(), name).getFirstChildWithName(
                    new QName(WSConstants.ENC_NS, WSConstants.ENC_DATA_LN));
            assertNotNull("wsa:" + name + " content must be encrypted", encrypted);
            assertEquals("content, not element, encryption",
                    WSConstants.ENC_NS + "Content", encrypted.getAttributeValue(new QName("Type")));
        }

        processAsService(ctx, policy);
        assertEquals("wsa:To must be back in the clear after processing",
                originalTo, header(ctx.getEnvelope(), "To").getText());
    }

    private static OMElement header(SOAPEnvelope env, String localName) {
        OMElement h = env.getHeader().getFirstChildWithName(new QName(WSA_NS, localName));
        assertNotNull("wsa:" + localName + " header missing", h);
        return h;
    }

    private static void processAsService(MessageContext ctx, Policy policy) throws Exception {
        SOAPEnvelope env = ctx.getEnvelope();
        ByteArrayInputStream in = new ByteArrayInputStream(env.toString().getBytes("UTF-8"));
        env = (SOAPEnvelope) new SOAPBuilder().processDocument(in, "text/xml", ctx);
        ctx.setEnvelope(env);

        ctx.setServerSide(true);
        AxisService axisService = ctx.getAxisService();
        Parameter clientSide = axisService.getParameter(RampartMessageData.PARAM_CLIENT_SIDE);
        if (clientSide != null) {
            axisService.removeParameter(clientSide);
        }
        ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
        ctx.setProperty(WSHandlerConstants.PW_CALLBACK_REF, new TestCBHandler());

        new RampartEngine().process(ctx);
    }
}
