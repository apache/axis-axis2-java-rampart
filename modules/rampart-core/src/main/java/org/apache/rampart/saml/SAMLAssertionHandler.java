/*
 * Copyright (c) The Apache Software Foundation.
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

package org.apache.rampart.saml;


import org.apache.axiom.om.OMElement;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rampart.TokenCallbackHandler;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;

import java.util.Date;

/**
 * A class to handle attributes to common SAML1 and SAML2 assertions.
 */
public abstract class SAMLAssertionHandler {


    private String assertionId;

    private Date dateNotBefore;

    private Date dateNotOnOrAfter;

    public String getAssertionId() {
        return assertionId;
    }

    protected void setAssertionId(String assertionId) {
        this.assertionId = assertionId;
    }

    public Date getDateNotBefore() {
        return dateNotBefore;
    }

    protected void setDateNotBefore(Date dateNotBefore) {
        this.dateNotBefore = dateNotBefore;
    }

    public Date getDateNotOnOrAfter() {
        return dateNotOnOrAfter;
    }

    protected void setDateNotOnOrAfter(Date dateNotOnOrAfter) {
        this.dateNotOnOrAfter = dateNotOnOrAfter;
    }

     /**
     * Checks whether SAML assertion is bearer - urn:oasis:names:tc:SAML:2.0:cm:bearer
     *
     * @return true if assertion is bearer else false.
     */
    public abstract boolean isBearerAssertion();

    protected abstract void processSAMLAssertion();


    /**
     * Gets the secret in assertion.
     * @param signatureCrypto Signature crypto info, private,public keys.
     * @param tokenCallbackHandler The token callback class. TODO Why ?
     * @return Secret as a byte array
     * @throws WSSecurityException If an error occurred while validating the signature.
     */
    public abstract byte[] getAssertionKeyInfoSecret(Crypto signatureCrypto, TokenCallbackHandler tokenCallbackHandler)
            throws WSSecurityException;

    /**
     * Gets the assertion element as an Axiom OMElement.
     * @return OMElement representation of assertion.
     * @throws TrustException if an error occurred while converting Assertion to an OMElement.
     */
    public abstract OMElement getAssertionElement() throws TrustException;
}
