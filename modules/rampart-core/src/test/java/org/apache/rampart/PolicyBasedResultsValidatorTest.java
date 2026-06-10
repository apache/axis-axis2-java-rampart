/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.rampart;

import java.io.ByteArrayInputStream;
import java.nio.charset.StandardCharsets;
import java.util.Arrays;
import java.util.Collections;

import javax.xml.parsers.DocumentBuilder;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.NodeList;

/**
 * Tests the signature-wrapping defence in {@link PolicyBasedResultsValidator}
 * (RAMPART-428): the SOAP Body the application consumes must be the very element
 * that was signed, identified by node identity rather than by element name.
 */
public class PolicyBasedResultsValidatorTest extends TestCase {

    private static final String SOAP_NS = "http://schemas.xmlsoap.org/soap/envelope/";

    // A signature-wrapping layout: the original (signed) Body is relocated into a
    // <wrapper> inside the header, and a new arbitrary Body sits in the Body position.
    private static final String WRAPPED =
            "<env:Envelope xmlns:env='" + SOAP_NS + "'>"
          + "  <env:Header>"
          + "    <wrapper xmlns=''>"
          + "      <env:Body env:id='signed'><echo>original</echo></env:Body>"
          + "    </wrapper>"
          + "  </env:Header>"
          + "  <env:Body><echo>arbitrary</echo></env:Body>"
          + "</env:Envelope>";

    private Document doc;
    private Element realBody;     // the Body the application consumes (Body position)
    private Element wrappedBody;  // the relocated, signed Body

    protected void setUp() throws Exception {
        DocumentBuilderFactory dbf = DocumentBuilderFactory.newInstance();
        // Secure the parser (OWASP): no DTDs / external entities.
        dbf.setFeature("http://apache.org/xml/features/disallow-doctype-decl", true);
        dbf.setFeature("http://xml.org/sax/features/external-general-entities", false);
        dbf.setFeature("http://xml.org/sax/features/external-parameter-entities", false);
        dbf.setXIncludeAware(false);
        dbf.setExpandEntityReferences(false);
        dbf.setNamespaceAware(true);
        DocumentBuilder db = dbf.newDocumentBuilder();
        doc = db.parse(new ByteArrayInputStream(WRAPPED.getBytes(StandardCharsets.UTF_8)));

        NodeList bodies = doc.getElementsByTagNameNS(SOAP_NS, "Body");
        assertEquals("test fixture should contain two Body elements", 2, bodies.getLength());
        // Document order: the wrapped (signed) Body comes first (inside the header),
        // the real consumed Body is the direct child of Envelope.
        wrappedBody = (Element) bodies.item(0);
        realBody = (Element) bodies.item(1);
        assertEquals("Envelope", realBody.getParentNode().getLocalName());
        assertEquals("wrapper", wrappedBody.getParentNode().getLocalName());
    }

    /** Wrapping attack: only the relocated copy is signed, so the real body must be rejected. */
    public void testWrappedBodyIsNotConsideredSigned() {
        assertFalse("a relocated same-name Body must not count as the signed body",
                PolicyBasedResultsValidator.isElementSigned(realBody, Collections.singletonList(wrappedBody)));
    }

    /** Legitimate case: the real consumed body is itself the signed element. */
    public void testActualSignedBodyIsAccepted() {
        assertTrue("the actual signed body must be recognised",
                PolicyBasedResultsValidator.isElementSigned(realBody, Collections.singletonList(realBody)));
    }

    /** Mixed set still matches by identity. */
    public void testAcceptedWhenRealBodyAmongSignedElements() {
        assertTrue(PolicyBasedResultsValidator.isElementSigned(
                realBody, Arrays.asList(wrappedBody, realBody)));
    }

    public void testNullInputsAreNotSigned() {
        assertFalse(PolicyBasedResultsValidator.isElementSigned(null, Collections.singletonList(realBody)));
        assertFalse(PolicyBasedResultsValidator.isElementSigned(realBody, null));
        assertFalse(PolicyBasedResultsValidator.isElementSigned(realBody, Collections.<Element>emptyList()));
    }
}
