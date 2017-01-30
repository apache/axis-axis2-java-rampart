/*
 * Copyright 2001-2004 The Apache Software Foundation.
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
package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Constants;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.model.UsernameToken;

public class UsernameTokenBuilder implements AssertionBuilder<OMElement> {
    
    private static Log log = LogFactory.getLog(UsernameTokenBuilder.class);
    
    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        UsernameToken usernameToken = new UsernameToken(SPConstants.SP_V12);
        
        OMAttribute attribute = element.getAttribute(SP12Constants.INCLUDE_TOKEN);
        
        if(attribute != null) {
            int inclusion = SP12Constants.getInclusionFromAttributeValue(attribute.getAttributeValue());
            usernameToken.setInclusion(inclusion);
        }
        
        OMAttribute isOptional = element.getAttribute(Constants.Q_ELEM_OPTIONAL_ATTR);
		if (isOptional != null) {
			usernameToken.setOptional(Boolean.valueOf(isOptional.getAttributeValue())
					.booleanValue());
		}
        
        OMElement policyElement = element.getFirstElement();
        
        if (policyElement != null && policyElement.getQName().equals(org.apache.neethi.Constants.Q_ELEM_POLICY)) {
        
            Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
            policy = (Policy) policy.normalize(false);
            
            for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
                processAlternative((List) iterator.next(), usernameToken);
                
                /*
                 * since there should be only one alternative
                 */
                break;
            }            
        }
        
        return usernameToken;
    }
        
    public QName[] getKnownElements() {
        return new QName[] {SP12Constants.USERNAME_TOKEN};
    }

    private void processAlternative(List assertions, UsernameToken parent) {
       
        // UT profile version
        boolean usernameToken10Set = false;
        boolean usernameToken11Set = false;
        // password options
        boolean noPasswordSet = false;
        boolean hasPasswordSet = false;
        // derived keys conf
        boolean derivedKeysSet = false;
        boolean expDerivedKeysSet = false;
        boolean impDerivedKeysSet = false;
             
        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            Assertion assertion = (Assertion) iterator.next();
            QName qname = assertion.getName();
            
            if (SP12Constants.WSS_USERNAME_TOKEN10.equals(qname)) {
                parent.setUseUTProfile10(true);  
                usernameToken10Set = true;
            } else if (SP12Constants.WSS_USERNAME_TOKEN11.equals(qname)) {
                parent.setUseUTProfile11(true);
                usernameToken11Set = true;
            } else if (SP12Constants.NO_PASSWORD.equals(qname)) {
                parent.setNoPassword(true);
                noPasswordSet = true;
            } else if (SP12Constants.HASH_PASSWORD.equals(qname)) {
                parent.setHashPassword(true);
                hasPasswordSet = true;
            } else if (SP12Constants.REQUIRE_DERIVED_KEYS.equals(qname)) {
                parent.setDerivedKeys(true);
                derivedKeysSet = true;
            } else if (SP12Constants.REQUIRE_EXPLICIT_DERIVED_KEYS.equals(qname)) {
                parent.setExplicitDerivedKeys(true);
                expDerivedKeysSet = true;
            } else if (SP12Constants.REQUIRE_IMPLIED_DERIVED_KEYS.equals(qname)) {
                parent.setImpliedDerivedKeys(true);
                impDerivedKeysSet = true;
            }
        }
        
        // doing a policy validation
        if(usernameToken10Set && usernameToken11Set || noPasswordSet && hasPasswordSet ||
                derivedKeysSet && expDerivedKeysSet || derivedKeysSet && impDerivedKeysSet ||
                impDerivedKeysSet && expDerivedKeysSet) {
            log.warn("Invalid UsernameToken Assertion in the policy. This may result an unexpected behaviour!");
        }
    }
}
