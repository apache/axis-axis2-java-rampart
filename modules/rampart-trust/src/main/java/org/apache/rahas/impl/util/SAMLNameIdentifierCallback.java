package org.apache.rahas.impl.util;

import org.apache.rahas.RahasData;
import org.opensaml.saml1.core.NameIdentifier;

/**
 * This is used retrieve data for the SAMLNameIdentifier.
 * SAMLNameIdentifier can have different formats.
 * Depending on it, NameIdentifier must have different values.
 * It should be implementation specific.
 *
 */
public class SAMLNameIdentifierCallback implements SAMLCallback{
    
    private NameIdentifier nameId = null;
    private String userId = null;
    private RahasData data = null;
    
    public SAMLNameIdentifierCallback(RahasData data){
        this.data = data;
    }
    
    public int getCallbackType(){
        return SAMLCallback.NAME_IDENTIFIER_CALLBACK;
    }

    public NameIdentifier getNameId() {
        return nameId;
    }

    public void setNameId(NameIdentifier nameId) {
        this.nameId = nameId;
    }

    public void setUserId(String userId) {
        this.userId = userId;
    }

    public String getUserId() {
        return userId;
    }

    public RahasData getData() {
        return data;
    }
    
}
