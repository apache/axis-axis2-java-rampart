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
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.handler.RequestData;

import java.time.Instant;

/**
 * A class to handle attributes to common SAML1 and SAML2 assertions.
 */
public abstract class SAMLAssertionHandler {


    private String assertionId;

    private Instant dateNotBefore;

    private Instant dateNotOnOrAfter;

    public String getAssertionId() {
        return assertionId;
    }

    protected void setAssertionId(String assertionId) {
        this.assertionId = assertionId;
    }

    public Instant getDateNotBefore() {
        return dateNotBefore;
    }

    protected void setDateNotBefore(Instant dateNotBefore) {
        this.dateNotBefore = dateNotBefore;
    }

    public Instant getDateNotOnOrAfter() {
        return dateNotOnOrAfter;
    }

    protected void setDateNotOnOrAfter(Instant dateNotOnOrAfter) {
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
     * @param tokenCallbackHandler The token callback class, required for WSS4J processing
     * @param requestData Allow customization of the numerous optional WSS4J params
     * @return Secret as a byte array
     * @throws WSSecurityException If an error occurred while validating the signature.
     */
    public abstract byte[] getAssertionKeyInfoSecret(Crypto signatureCrypto, TokenCallbackHandler tokenCallbackHandler, RequestData requestData)
            throws WSSecurityException;

    /**
     * Gets the assertion element as an Axiom OMElement.
     * @return OMElement representation of assertion.
     * @throws TrustException if an error occurred while converting Assertion to an OMElement.
     */
    public abstract OMElement getAssertionElement() throws TrustException;
}
