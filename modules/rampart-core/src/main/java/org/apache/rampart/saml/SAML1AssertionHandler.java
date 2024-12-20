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
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.SAMLUtils;
import org.apache.rampart.TokenCallbackHandler;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.saml.SAMLKeyInfo;
import org.apache.wss4j.common.saml.SAMLUtil;
import org.apache.wss4j.dom.WSDocInfo;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.saml.WSSSAMLKeyInfoProcessor;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.Conditions;

/**
 * This class handles SAML1 assertions.Processes SAML1 assertion and will extract SAML1 attributes
 * such as assertion id, start date, end date etc ...
 */
public class SAML1AssertionHandler extends SAMLAssertionHandler{

    private Assertion assertion;

    public SAML1AssertionHandler(Assertion saml1Assertion) {
        this.assertion = saml1Assertion;
        this.processSAMLAssertion();
    }

    @Override
    public boolean isBearerAssertion() {
        return RahasConstants.SAML11_SUBJECT_CONFIRMATION_BEARER.equals(
                            SAMLUtils.getSAML11SubjectConfirmationMethod(assertion));
    }

    @Override
    protected void processSAMLAssertion() {

        this.setAssertionId(assertion.getID());

        //Read the validity period from the 'Conditions' element, else read it from SC Data
        if (assertion.getConditions() != null) {
            Conditions conditions = assertion.getConditions();
            if (conditions.getNotBefore() != null) {
                this.setDateNotBefore(conditions.getNotBefore());
            }
            if (conditions.getNotOnOrAfter() != null) {
                this.setDateNotOnOrAfter(conditions.getNotOnOrAfter());
            }
        }
    }

    @Override
    public byte[] getAssertionKeyInfoSecret(Crypto signatureCrypto, TokenCallbackHandler tokenCallbackHandler, RequestData requestData) throws WSSecurityException {

        requestData.setCallbackHandler(tokenCallbackHandler);
        requestData.setSigVerCrypto(signatureCrypto);

        WSDocInfo docInfo = new WSDocInfo(assertion.getDOM().getOwnerDocument()); // TODO Improve ..
        // TODO change this to use SAMLAssertion parameter once wss4j conversion is done ....
        SAMLKeyInfo samlKi = SAMLUtil.getCredentialFromSubject(assertion, new WSSSAMLKeyInfoProcessor(requestData), signatureCrypto);
        return samlKi.getSecret();
    }


    @Override
    public OMElement getAssertionElement() throws TrustException {
        return (OMElement)this.assertion.getDOM();
    }


}
