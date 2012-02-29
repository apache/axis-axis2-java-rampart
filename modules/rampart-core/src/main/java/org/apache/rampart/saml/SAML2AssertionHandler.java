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
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.SAML2KeyInfo;
import org.apache.rahas.impl.util.SAML2Utils;
import org.apache.rampart.TokenCallbackHandler;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.opensaml.saml2.core.Assertion;
import org.opensaml.saml2.core.Conditions;
import org.opensaml.saml2.core.Subject;
import org.opensaml.saml2.core.SubjectConfirmationData;


/**
 * This class handles SAML2 assertions.Processes SAML2 assertion and will extract SAML2 attributes
 * such as assertion id, start date, end date etc ...
 */
public class SAML2AssertionHandler extends SAMLAssertionHandler{

    private static final Log log = LogFactory.getLog(SAML2AssertionHandler.class);

    private Assertion assertion;


    public SAML2AssertionHandler(Assertion samlAssertion) {
        this.assertion = samlAssertion;
        this.processSAMLAssertion();
    }

    /**
     * Checks whether SAML assertion is bearer - urn:oasis:names:tc:SAML:2.0:cm:bearer
     *
     * @return true if assertion is bearer else false.
     */
    public boolean isBearerAssertion() {

        // if the subject confirmation method is Bearer, do not try to get the KeyInfo
        return SAML2Utils.getSAML2SubjectConfirmationMethod(assertion).equals(
                RahasConstants.SAML20_SUBJECT_CONFIRMATION_BEARER);
    }

    protected void processSAMLAssertion() {

        this.setAssertionId(assertion.getID());

        Subject subject = assertion.getSubject();

        //Read the validity period from the 'Conditions' element, else read it from SC Data
        if (assertion.getConditions() != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions.getNotBefore() != null) {
                this.setDateNotBefore(conditions.getNotBefore().toDate());
            }
            if (conditions.getNotOnOrAfter() != null) {
                this.setDateNotOnOrAfter(conditions.getNotOnOrAfter().toDate());
            }
        } else {
            SubjectConfirmationData scData = subject.getSubjectConfirmations()
                    .get(0).getSubjectConfirmationData();
            if (scData.getNotBefore() != null) {
                this.setDateNotBefore(scData.getNotBefore().toDate());
            }
            if (scData.getNotOnOrAfter() != null) {
                this.setDateNotOnOrAfter(scData.getNotOnOrAfter().toDate());
            }
        }

    }

    public byte[] getAssertionKeyInfoSecret(Crypto signatureCrypto, TokenCallbackHandler tokenCallbackHandler)
            throws WSSecurityException {
        // TODO : SAML2KeyInfo element needs to be moved to WSS4J.
        SAML2KeyInfo saml2KeyInfo = SAML2Utils.
                getSAML2KeyInfo(assertion, signatureCrypto, tokenCallbackHandler);

        return saml2KeyInfo.getSecret();
    }

    public OMElement getAssertionElement() throws TrustException{
        try {
            return (OMElement) SAML2Utils.getElementFromAssertion(assertion);
        } catch (TrustException e) {
            log.error("Error getting Axiom representation of SAML2 assertion.", e);
            throw e;
        }
    }



}
