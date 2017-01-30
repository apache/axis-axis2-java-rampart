package org.apache.ws.secpolicy11.builders;

import java.io.FileInputStream;

import junit.framework.TestCase;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.neethi.AssertionBuilderFactoryImpl;
import org.apache.neethi.PolicyBuilder;
import org.apache.ws.secpolicy.model.UsernameToken;

public class UsernameTokenBuilderTest extends TestCase {
    
    public UsernameTokenBuilderTest(String name){
        super(name);
    }

    AssertionBuilderFactoryImpl factory = new AssertionBuilderFactoryImpl(new PolicyBuilder());
    UsernameTokenBuilder utBuilder = new UsernameTokenBuilder();
    OMElement utElement = null; 
    UsernameToken ut = null;
    
    public void testNoPolicyAlternatives() throws Exception {
        
        String xmlPath = "test-resources/policy/assertions/username-token-assertion-1.1-nopolicy.xml";
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        utElement = builder.getDocumentElement();
        ut = (UsernameToken) utBuilder.build(utElement, factory);

        assertEquals(false, ut.isUseUTProfile10());
        assertEquals(false, ut.isUseUTProfile11());
    }
    
    public void testUT11Profile() throws Exception {
        
        String xmlPath = "test-resources/policy/assertions/username-token-assertion-1.1-ut11prof.xml";
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        utElement = builder.getDocumentElement();
        ut = (UsernameToken) utBuilder.build(utElement, factory);
        
        assertEquals(false, ut.isUseUTProfile10());
        assertEquals(true, ut.isUseUTProfile11());
    }
    
}
