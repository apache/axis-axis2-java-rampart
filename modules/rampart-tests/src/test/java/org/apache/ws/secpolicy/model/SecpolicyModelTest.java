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

package org.apache.ws.secpolicy.model;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.ws.secpolicy.SPConstants;

import java.io.FileInputStream;
import java.util.Iterator;
import java.util.List;

import junit.framework.TestCase;

public class SecpolicyModelTest extends TestCase {
    
    
    public void testSymmBinding() throws Exception {
        Policy p = this.getPolicy("test-resources/policy-symm-binding.xml");
        List<Assertion> assertions = (List<Assertion>)p.getAlternatives().next();
        
        boolean symmBindingFound = false;
        
        for (Iterator<Assertion> iter = assertions.iterator(); iter.hasNext();) {
            Assertion assertion = iter.next();
            if(assertion instanceof SymmetricBinding) {
                symmBindingFound = true;
                SymmetricBinding binding = (SymmetricBinding)assertion;
                assertEquals("IncludeTimestamp assertion not processed", true, binding.isIncludeTimestamp());
                
                ProtectionToken protectionToken = binding.getProtectionToken();
                assertNotNull("ProtectionToken missing", protectionToken);
                
                Token token = protectionToken.getProtectionToken();
                if(token instanceof X509Token) {
                    assertEquals("incorrect X509 token versin and type",
                            SPConstants.WSS_X509_V3_TOKEN10,
                            ((X509Token) token).getTokenVersionAndType());
                } else {
                    fail("ProtectionToken must contain a X509Token assertion");
                }
                
            }
        }
        //The Asymm binding mean is not built in the policy processing :-(
        assertTrue("SymmetricBinding not porcessed",  symmBindingFound);
    }
    
    public void testAsymmBinding() throws Exception {
        this.getPolicy("test-resources/policy-asymm-binding.xml");
    }

    public void testTransportBinding() throws Exception {
        this.getPolicy("test-resources/policy-transport-binding.xml");
    }
    
    public void testSymmBindingWithBothProtectionTokenAndEncryptionToken() throws Exception {
    	boolean exceptionThrown = false;
    	try {
    		this.getPolicy("test-resources/policy-symm-binding-fault1.xml");
    	} catch (IllegalArgumentException e) {
    		exceptionThrown = true;
    	}
    	assertTrue("Policy cannot contain both ProtectionToken and EncryptionToken",
    			exceptionThrown);
    }
    
    private Policy getPolicy(String filePath) throws Exception {
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(filePath));
        OMElement elem = builder.getDocumentElement();
        return PolicyEngine.getPolicy(elem);
    }
}
