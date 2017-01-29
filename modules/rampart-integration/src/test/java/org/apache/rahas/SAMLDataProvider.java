package org.apache.rahas;

import org.apache.rahas.impl.util.*;
import org.opensaml.common.SAMLException;
import org.opensaml.saml1.core.Attribute;
import org.opensaml.saml1.core.NameIdentifier;

public class SAMLDataProvider implements SAMLCallbackHandler{
	
	public void handle(SAMLCallback callback) throws SAMLException {
		
		if(callback.getCallbackType() == SAMLCallback.ATTR_CALLBACK){
			SAMLAttributeCallback cb = (SAMLAttributeCallback)callback;

            try {
                Attribute attribute = SAMLUtils.createAttribute("Name", "https://rahas.apache.org/saml/attrns", "Custom/Rahas");
                cb.addAttributes(attribute);
            } catch (TrustException e) {
                throw new SAMLException("Error creating attribute", e);
            }

		}else if(callback.getCallbackType() == SAMLCallback.NAME_IDENTIFIER_CALLBACK){
			SAMLNameIdentifierCallback cb = (SAMLNameIdentifierCallback)callback;
            try {
                NameIdentifier nameId = SAMLUtils.createNamedIdentifier("David", NameIdentifier.EMAIL);
                cb.setNameId(nameId);
            } catch (TrustException e) {
                throw new SAMLException("Error creating name identifier", e);
            }
		}
		
	}
}
