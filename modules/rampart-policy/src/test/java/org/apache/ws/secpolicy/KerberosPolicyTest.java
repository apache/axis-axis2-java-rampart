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
package org.apache.ws.secpolicy;

import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.StringReader;
import java.io.StringWriter;
import java.io.Writer;
import java.util.ArrayList;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import junit.framework.TestCase;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.neethi.All;
import org.apache.neethi.Assertion;
import org.apache.neethi.ExactlyOne;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyEngine;
import org.apache.ws.secpolicy.model.KerberosToken;
import org.apache.ws.secpolicy.model.SupportingToken;
import org.apache.ws.secpolicy.model.Token;
import org.custommonkey.xmlunit.XMLAssert;
import org.custommonkey.xmlunit.XMLUnit;
import org.xml.sax.SAXException;

/**
 * Tests building and serialization of {@link KerberosToken} assertion.
 */
public class KerberosPolicyTest extends TestCase {
    private boolean isXmlUnitIgnoreWhitespace;

    @Override
    protected void setUp() throws Exception {
        isXmlUnitIgnoreWhitespace = XMLUnit.getIgnoreWhitespace();
        XMLUnit.setIgnoreWhitespace(true);
    }

    @Override
    protected void tearDown() throws Exception {
        XMLUnit.setIgnoreWhitespace(isXmlUnitIgnoreWhitespace);
    }
    
    public void testKerberosGssKeyRefPolicy11() throws Exception {
        System.out.println(getName());
        File policyFile = new File("src/test/resources/policy/kerberos-gss-keyref-11.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP11Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP11Constants.KERBEROS_TOKEN, true, true, false);
        assertPolicyEquals(policyFile, policy);
    }

    public void testKerberosGssPolicy11() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-gss-11.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP11Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP11Constants.KERBEROS_TOKEN, false, true, false);
        assertPolicyEquals(policyFile, policy);
    }
    
    public void testKerberosKeyRefPolicy11() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-keyref-11.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP11Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP11Constants.KERBEROS_TOKEN, true, false, true);
        assertPolicyEquals(policyFile, policy);
    }
    
    public void testKerberosPolicy11() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-11.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP11Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP11Constants.KERBEROS_TOKEN, false, false, true);
        assertPolicyEquals(policyFile, policy);
    }
    
    public void testKerberosGssKeyRefPolicy12() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-gss-keyref-12.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP12Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP12Constants.KERBEROS_TOKEN, true, true, false);
        assertPolicyEquals(policyFile, policy);
    }

    public void testKerberosGssPolicy12() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-gss-12.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP12Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP12Constants.KERBEROS_TOKEN, false, true, false);
        assertPolicyEquals(policyFile, policy);
    }
    
    public void testKerberosKeyRefPolicy12() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-keyref-12.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP12Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP12Constants.KERBEROS_TOKEN, true, false, true);
        assertPolicyEquals(policyFile, policy);
    }
    
    public void testKerberosPolicy12() throws Exception {
        File policyFile = new File("src/test/resources/policy/kerberos-12.xml");
        Policy policy = loadPolicy(policyFile);
        KerberosToken kerberosToken = getKerberosEndorsingSupportingToken(policyFile, policy, SP12Constants.SP_NS);
        assertKerberosTokenMatches(kerberosToken, SP12Constants.KERBEROS_TOKEN, false, false, true);
        assertPolicyEquals(policyFile, policy);
    }
    
    private KerberosToken getKerberosEndorsingSupportingToken(File policyFile, Policy policy, String namespace) throws XMLStreamException {
        ExactlyOne exactlyOne = (ExactlyOne) policy.getAssertions().get(0);
        All all = (All) exactlyOne.getFirstPolicyComponent();
        List<PolicyComponent> assertions = all.getAssertions();
        
        QName endSuppTokens = new QName(namespace, SPConstants.ENDORSING_SUPPORTING_TOKENS);
        SupportingToken endorsingSupportingTokens = (SupportingToken) findAssertion(assertions, endSuppTokens);
        assertNotNull(String.format("Cannot find any '%s' assertion in policy: %s", endSuppTokens, printPolicy(policy)), endorsingSupportingTokens);
        
        ArrayList<Token> supportingTokens = endorsingSupportingTokens.getTokens();
        assertTrue(String.format("Cannot find any supporting tokens in policy: %s", printPolicy(policy)), supportingTokens.size() > 0);

        KerberosToken kerberosToken = findKerberosToken(supportingTokens);
        assertNotNull(String.format("Cannot find any Kerberos token in policy: %s", printPolicy(policy)), kerberosToken);
        
        return kerberosToken;
    }
    
    private void assertKerberosTokenMatches(KerberosToken kerberosToken, QName expectedName, boolean requiresKeyIdentifierRef,
        boolean requiresGssKerberosV5, boolean requiresKerberosV5) {
        assertTrue(String.format("Expected KerberosToken '%s' but got: %s", expectedName, kerberosToken.getName()),
            expectedName.equals(kerberosToken.getName()));
        assertEquals("Expected Kerberos token that must be included once.", SPConstants.INCLUDE_TOKEN_ONCE, kerberosToken.getInclusion());
        assertEquals("Expected KerberosToken that " + (requiresKeyIdentifierRef ? "requires" : "does NOT require") + " key identifier reference",
            requiresKeyIdentifierRef, kerberosToken.isRequiresKeyIdentifierReference());
        assertEquals("Expected KerberosToken that " + (requiresGssKerberosV5 ? "requires" : "does NOT require") + " GSS-API KerberosV5 mechanism token", 
            requiresGssKerberosV5, kerberosToken.isRequiresGssKerberosV5Token());
        assertEquals("Expected KerberosToken that " + (requiresGssKerberosV5 ? "requires" : "does NOT require") + " KerberosV5 mechanism token", 
            requiresKerberosV5, kerberosToken.isRequiresKerberosV5Token());
    }
    
    private void assertPolicyEquals(File expected, Policy actual) throws IOException, XMLStreamException, SAXException {
        StringWriter writer = new StringWriter();
        serializePolicy(actual, writer);
        
        XMLAssert.assertXMLEqual(String.format("Serialized policy '%s' differs from control policy '%s'", writer.toString(), printPolicy(actual)),
            new FileReader(expected), new StringReader(writer.toString()));
    }
    
    private Policy loadPolicy(File file) throws IOException {
        FileReader reader = null;
        try {
            reader = new FileReader(file);
            OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(reader);
            OMElement policyElement = builder.getDocumentElement();
            return PolicyEngine.getPolicy(policyElement);
        }
        finally {
            if (reader != null) {
                reader.close();
            }
        }
    }

    private String serializePolicy(Policy policy, Writer writer) throws XMLStreamException {
        StringWriter stringWriter = new StringWriter();
        XMLStreamWriter xmlWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(writer);
        policy.serialize(xmlWriter);
        xmlWriter.flush();
        
        return stringWriter.toString();
    }
    
    private String printPolicy(Policy policy) throws XMLStreamException {
        StringWriter writer = new StringWriter();
        serializePolicy(policy, writer);
        
        return writer.toString();
    }
    
    private Assertion findAssertion(List<PolicyComponent> policyComponents, QName name) {
        for (PolicyComponent policyComponent : policyComponents) {
            if (policyComponent instanceof Assertion && ((Assertion)policyComponent).getName().equals(name)) {
                return (Assertion)policyComponent;
            }
        }
        
        return null;
    }
    
    private KerberosToken findKerberosToken(ArrayList<Token> tokens) {
        for (Token token : tokens) {
            if (token instanceof KerberosToken) {
                return (KerberosToken)token;
            }
        }
        
        return null;
    }
}
