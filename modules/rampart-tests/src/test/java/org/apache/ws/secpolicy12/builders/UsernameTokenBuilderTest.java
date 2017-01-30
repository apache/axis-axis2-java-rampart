package org.apache.ws.secpolicy12.builders;

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
        
        String xmlPath = "test-resources/policy/assertions/username-token-assertion-1.2-nopolicy.xml";
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        utElement = builder.getDocumentElement();
        ut = (UsernameToken) utBuilder.build(utElement, factory);
        
        assertEquals(false, ut.isNoPassword());
        assertEquals(false, ut.isHashPassword());
        assertEquals(false, ut.isDerivedKeys());
        assertEquals(false, ut.isExplicitDerivedKeys());
        assertEquals(false, ut.isImpliedDerivedKeys());
        assertEquals(false, ut.isUseUTProfile10());
        assertEquals(false, ut.isUseUTProfile11());
        
    }
    
    public void testNoPassword() throws Exception {
        
        String xmlPath = "test-resources/policy/assertions/username-token-assertion-1.2-nopwd.xml";
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        utElement = builder.getDocumentElement();
        ut = (UsernameToken) utBuilder.build(utElement, factory);
        
        assertEquals(true, ut.isNoPassword());
        assertEquals(false, ut.isHashPassword());
        assertEquals(true, ut.isDerivedKeys());
        assertEquals(false, ut.isExplicitDerivedKeys());
        assertEquals(false, ut.isImpliedDerivedKeys());
        assertEquals(true, ut.isUseUTProfile10());
        assertEquals(false, ut.isUseUTProfile11());
    }
    
    public void testHashPassword() throws Exception {
        
        String xmlPath = "test-resources/policy/assertions/username-token-assertion-1.2-hashpwd.xml";
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        utElement = builder.getDocumentElement();
        ut = (UsernameToken) utBuilder.build(utElement, factory);
        
        assertEquals(false, ut.isNoPassword());
        assertEquals(true, ut.isHashPassword());
        assertEquals(false, ut.isDerivedKeys());
        assertEquals(false, ut.isExplicitDerivedKeys());
        assertEquals(false, ut.isImpliedDerivedKeys());
        assertEquals(false, ut.isUseUTProfile10());
        assertEquals(true, ut.isUseUTProfile11());
        
    }
    
}
