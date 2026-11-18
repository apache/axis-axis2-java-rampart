package org.apache.rahas.impl.util;

import org.apache.rahas.RahasData;
import org.opensaml.saml.saml1.core.NameIdentifier;
import org.opensaml.saml.saml2.core.NameID;

/**
 * This is used retrieve data for the SAMLNameIdentifier.
 * SAMLNameIdentifier can have different formats.
 * Depending on it, NameIdentifier must have different values.
 * It should be implementation specific.
 * <p>
 * The SAML 1.1 issuer reads {@link #getNameId()}; the SAML 2.0 issuer reads
 * {@link #getSAML2NameID()}. A handler that leaves the relevant one null gets
 * the issuer's default: the user id in the email address format.
 */
public class SAMLNameIdentifierCallback implements SAMLCallback{

    private NameIdentifier nameId = null;
    private NameID saml2NameID = null;
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

    /**
     * @return The SAML 2.0 subject NameID supplied by the handler, or null.
     */
    public NameID getSAML2NameID() {
        return saml2NameID;
    }

    /**
     * Supplies the SAML 2.0 subject NameID, including its Format.
     * @param saml2NameID The NameID to put in the assertion's Subject.
     */
    public void setSAML2NameID(NameID saml2NameID) {
        this.saml2NameID = saml2NameID;
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
