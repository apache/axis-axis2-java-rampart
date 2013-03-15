package org.apache.ws.secpolicy12.builders;

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.EncryptionToken;
import org.apache.ws.secpolicy.model.Token;

public class EncryptionTokenBuilder  implements AssertionBuilder<OMElement> {

    public Assertion build(OMElement element, AssertionBuilderFactory factory) throws IllegalArgumentException {
        EncryptionToken encrToken = new EncryptionToken(SPConstants.SP_V12);
        
        Policy policy = PolicyEngine.getPolicy(element.getFirstElement());
        policy = (Policy) policy.normalize(false);
        
        for (Iterator<List<Assertion>> iterator = policy.getAlternatives(); iterator.hasNext();) {
            processAlternative(iterator.next(), encrToken);
            break; // since there should be only one alternative ..
        }
        
        return encrToken;
    }
        
    public QName[] getKnownElements() {
        return new QName[] {SP12Constants.ENCRYPTION_TOKEN};
    }

    private void processAlternative(List<Assertion> assertions, EncryptionToken parent) {
        Object token = assertions.get(0);
        
        if (token instanceof Token) {
            parent.setToken((Token) token);
        }
    }
}
