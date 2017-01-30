/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.ws.secpolicy.model;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SPConstants;

/**
 * Model bean to capture Trust10 assertion info
 */
public class Trust10 extends AbstractSecurityAssertion {

    private boolean mustSupportClientChallenge;
    private boolean mustSupportServerChallenge;
    private boolean requireClientEntropy;
    private boolean requireServerEntropy;
    private boolean mustSupportIssuedTokens;
    
    public Trust10(int version){
        setVersion(version);
    }
    
    /**
     * @return Returns the mustSupportClientChallenge.
     */
    public boolean isMustSupportClientChallenge() {
        return mustSupportClientChallenge;
    }

    /**
     * @param mustSupportClientChallenge The mustSupportClientChallenge to set.
     */
    public void setMustSupportClientChallenge(boolean mustSupportClientChallenge) {
        this.mustSupportClientChallenge = mustSupportClientChallenge;
    }

    /**
     * @return Returns the mustSupportIssuedTokens.
     */
    public boolean isMustSupportIssuedTokens() {
        return mustSupportIssuedTokens;
    }

    /**
     * @param mustSupportIssuedTokens The mustSupportIssuedTokens to set.
     */
    public void setMustSupportIssuedTokens(boolean mustSupportIssuedTokens) {
        this.mustSupportIssuedTokens = mustSupportIssuedTokens;
    }

    /**
     * @return Returns the mustSupportServerChallenge.
     */
    public boolean isMustSupportServerChallenge() {
        return mustSupportServerChallenge;
    }

    /**
     * @param mustSupportServerChallenge The mustSupportServerChallenge to set.
     */
    public void setMustSupportServerChallenge(boolean mustSupportServerChallenge) {
        this.mustSupportServerChallenge = mustSupportServerChallenge;
    }

    /**
     * @return Returns the requireClientEntropy.
     */
    public boolean isRequireClientEntropy() {
        return requireClientEntropy;
    }

    /**
     * @param requireClientEntropy The requireClientEntropy to set.
     */
    public void setRequireClientEntropy(boolean requireClientEntropy) {
        this.requireClientEntropy = requireClientEntropy;
    }

    /**
     * @return Returns the requireServerEntropy.
     */
    public boolean isRequireServerEntropy() {
        return requireServerEntropy;
    }

    /**
     * @param requireServerEntropy The requireServerEntropy to set.
     */
    public void setRequireServerEntropy(boolean requireServerEntropy) {
        this.requireServerEntropy = requireServerEntropy;
    }

    /* (non-Javadoc)
     * @see org.apache.neethi.Assertion#getName()
     */
    public QName getName() {
            return SP11Constants.TRUST_10;
    }

    /* (non-Javadoc)
     * @see org.apache.neethi.Assertion#isOptional()
     */
    public boolean isOptional() {
        // TODO TODO Sanka
        throw new UnsupportedOperationException("TODO Sanka");
    }

    public PolicyComponent normalize() {
        return this;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        
        String prefix = getName().getPrefix();
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();
        
        // <sp:Trust10>
        writeStartElement(writer, prefix, localname, namespaceURI);
        
        // <wsp:Policy>
        writeStartElement(writer, SPConstants.POLICY);
        
        if (isMustSupportClientChallenge()) {
            // <sp:MustSupportClientChallenge />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_CLIENT_CHALLENGE, namespaceURI);
        }
        
        if (isMustSupportServerChallenge()) {
            // <sp:MustSupportServerChallenge />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_SERVER_CHALLENGE, namespaceURI);
        }
        
        if (isRequireClientEntropy()) {
            // <sp:RequireClientEntropy />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_CLIENT_ENTROPY, namespaceURI);
        }
        
        
        if (isRequireServerEntropy()) {
            // <sp:RequireServerEntropy />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_SERVER_ENTROPY, namespaceURI);
        }
        
        if (isMustSupportIssuedTokens()) {
            // <sp:MustSupportIssuedTokens />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_ISSUED_TOKENS, namespaceURI);
        }
        
        // </wsp:Policy>
        writer.writeEndElement();
        
        
        // </sp:Trust10>
        writer.writeEndElement();
        
        
        
        
    }

    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }

}
