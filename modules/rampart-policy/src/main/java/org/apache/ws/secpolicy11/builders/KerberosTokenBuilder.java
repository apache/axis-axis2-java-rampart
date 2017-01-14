/*
 * Copyright 2001-2014 The Apache Software Foundation.
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
package org.apache.ws.secpolicy11.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.KerberosToken;

/**
 * Builder for {@link KerberosToken} assertion (WS Security Policy version 1.1)
 */
public class KerberosTokenBuilder implements AssertionBuilder<OMElement> {

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.neethi.builders.AssertionBuilder#build(java.lang.Object,
     * org.apache.neethi.AssertionBuilderFactory)
     */
	public Assertion build(OMElement element, AssertionBuilderFactory arg1) 
	    throws IllegalArgumentException {
        KerberosToken kerberosToken = new KerberosToken(SPConstants.SP_V11);

        OMElement policyElement = element.getFirstElement();

        // Process token inclusion
        OMAttribute includeAttr = element.getAttribute(SP11Constants.INCLUDE_TOKEN);

        if (includeAttr != null) {
            int inclusion = SP11Constants.getInclusionFromAttributeValue(
                                  includeAttr.getAttributeValue());
            kerberosToken.setInclusion(inclusion);
        }

        if (policyElement != null) {
            Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
            policy = (Policy) policy.normalize(false);
            for (Iterator iterator = policy.getAlternatives(); iterator.hasNext();) {
                processAlternative((List) iterator.next(), kerberosToken);
                 // there should be only one alternative
                break;
            }
        }
        return kerberosToken;
    }

    private void processAlternative(List assertions, KerberosToken parent) {
        Assertion assertion;
        QName name;

        for (Iterator iterator = assertions.iterator(); iterator.hasNext();) {
            assertion = (Assertion) iterator.next();
            name = assertion.getName();
            if (SP11Constants.REQUIRE_KERBEROS_V5_TOKEN_11.equals(name)) {
                parent.setRequiresKerberosV5Token(true);
            } else if (SP11Constants.REQUIRE_KERBEROS_GSS_V5_TOKEN_11.equals(name)) {
                parent.setRequiresGssKerberosV5Token(true);
            } else if (SP11Constants.REQUIRE_KEY_IDENTIFIRE_REFERENCE.equals(name)) {
                parent.setRequiresKeyIdentifierReference(true);
            }
        }
    }

    public QName[] getKnownElements() {
        return new QName[] { SP11Constants.KERBEROS_TOKEN };
    }
}
