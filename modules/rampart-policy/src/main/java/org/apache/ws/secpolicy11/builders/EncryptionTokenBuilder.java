/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.ws.secpolicy11.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.EncryptionToken;
import org.apache.ws.secpolicy.model.Token;

public class EncryptionTokenBuilder  implements AssertionBuilder<OMElement> {

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        EncryptionToken encrToken = new EncryptionToken(SPConstants.SP_V11);
        
        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);
        
        for (Iterator<List<Assertion>> iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative(iterator.next(), encrToken);
            break; // since there should be only one alternative ..
        }
        
        return encrToken;
    }
        
    public QName[] getKnownElements() {
        return new QName[] {SP11Constants.ENCRYPTION_TOKEN};
    }

    private void processAlternative(List<Assertion> assertions, EncryptionToken parent) {
        Object token = assertions.get(0);
        
        if (token instanceof Token) {
            parent.setToken((Token) token);
        }
    }
}
