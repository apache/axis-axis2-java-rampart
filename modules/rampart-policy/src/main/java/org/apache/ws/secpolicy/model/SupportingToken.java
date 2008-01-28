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

import java.util.ArrayList;
import java.util.Iterator;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class SupportingToken extends AbstractSecurityAssertion implements
        AlgorithmWrapper, TokenWrapper {

    /**
     * Type of SupportingToken
     * 
     * @see SupportingToken#SUPPORTING
     * @see SupportingToken#ENDORSING
     * @see SupportingToken#SIGNED
     * @see SupportingToken#SIGNED_ENDORSING
     */
    private int type;

    private AlgorithmSuite algorithmSuite;

    private ArrayList tokens = new ArrayList();

    private SignedEncryptedElements signedElements;

    private SignedEncryptedElements encryptedElements;

    private SignedEncryptedParts signedParts;

    private SignedEncryptedParts encryptedParts;

    public SupportingToken(int type, int version ) {
        this.type = type;
        setVersion(version);
    }
    
    /**
     * @return Returns the algorithmSuite.
     */
    public AlgorithmSuite getAlgorithmSuite() {
        return algorithmSuite;
    }

    /**
     * @param algorithmSuite
     *            The algorithmSuite to set.
     */
    public void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    /**
     * @return Returns the token.
     */
    public ArrayList getTokens() {
        return tokens;
    }

    /**
     * @param token
     *            The token to set.
     */
    public void addToken(Token token) {
        this.tokens.add(token);
    }

    /**
     * @return Returns the type.
     */
    public int getTokenType() {
        return type;
    }

    /**
     * @param type
     *            The type to set.
     */
    public void setTokenType(int type) {
        this.type = type;
    }

    /**
     * @return Returns the encryptedElements.
     */
    public SignedEncryptedElements getEncryptedElements() {
        return encryptedElements;
    }

    /**
     * @param encryptedElements
     *            The encryptedElements to set.
     */
    public void setEncryptedElements(SignedEncryptedElements encryptedElements) {
        this.encryptedElements = encryptedElements;
    }

    /**
     * @return Returns the encryptedParts.
     */
    public SignedEncryptedParts getEncryptedParts() {
        return encryptedParts;
    }

    /**
     * @param encryptedParts
     *            The encryptedParts to set.
     */
    public void setEncryptedParts(SignedEncryptedParts encryptedParts) {
        this.encryptedParts = encryptedParts;
    }

    /**
     * @return Returns the signedElements.
     */
    public SignedEncryptedElements getSignedElements() {
        return signedElements;
    }

    /**
     * @param signedElements
     *            The signedElements to set.
     */
    public void setSignedElements(SignedEncryptedElements signedElements) {
        this.signedElements = signedElements;
    }

    /**
     * @return Returns the signedParts.
     */
    public SignedEncryptedParts getSignedParts() {
        return signedParts;
    }

    /**
     * @param signedParts
     *            The signedParts to set.
     */
    public void setSignedParts(SignedEncryptedParts signedParts) {
        this.signedParts = signedParts;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.ws.security.policy.TokenWrapper#setToken(org.apache.ws.security.policy.Token)
     */
    public void setToken(Token tok) {
        this.addToken(tok);
    }

    public QName getName() {
        switch (type) {
        case SPConstants.SUPPORTING_TOKEN_SUPPORTING:
            return version == SPConstants.SP_V12 ? SP12Constants.SUPPORTING_TOKENS : 
                                                                    SP11Constants.SUPPORTING_TOKENS;
        case SPConstants.SUPPORTING_TOKEN_SIGNED:
            return version == SPConstants.SP_V12 ? SP12Constants.SIGNED_SUPPORTING_TOKENS : 
                                                             SP11Constants.SIGNED_SUPPORTING_TOKENS;
        case SPConstants.SUPPORTING_TOKEN_ENDORSING:
            return version == SPConstants.SP_V12 ? SP12Constants.ENDORSING_SUPPORTING_TOKENS :
                                                          SP11Constants.ENDORSING_SUPPORTING_TOKENS;
        case SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING:
            return version == SPConstants.SP_V12 ? SP12Constants.SIGNED_ENDORSING_SUPPORTING_TOKENS: 
                                                   SP11Constants.SIGNED_ENDORSING_SUPPORTING_TOKENS;
        default:
            return null;
        }
    }

    public PolicyComponent normalize() {
        return this;
    }

    public short getType() {
        return org.apache.neethi.Constants.TYPE_ASSERTION;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);
        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        String localname = null;

        switch (getTokenType()) {
        case SPConstants.SUPPORTING_TOKEN_SUPPORTING:
            localname = SPConstants.SUPPORTING_TOKENS;
            break;
        case SPConstants.SUPPORTING_TOKEN_SIGNED:
            localname = SPConstants.SIGNED_SUPPORTING_TOKENS;
            break;
        case SPConstants.SUPPORTING_TOKEN_ENDORSING:
            localname = SPConstants.ENDORSING_SUPPORTING_TOKENS;
            break;
        case SPConstants.SUPPORTING_TOKEN_SIGNED_ENDORSING:
            localname = SPConstants.SIGNED_ENDORSING_SUPPORTING_TOKENS;
            break;
        default:
            throw new RuntimeException("Invalid SupportingTokenType");
        }

        // <sp:SupportingToken>
        writer.writeStartElement(prefix, localname, namespaceURI);
        
        // xmlns:sp=".."
        writer.writeNamespace(prefix, namespaceURI);

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }
        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(),
                SPConstants.POLICY.getNamespaceURI());

        Token token;
        for (Iterator iterator = getTokens().iterator(); iterator.hasNext();) {
            // [Token Assertion] +
            token = (Token) iterator.next();
            token.serialize(writer);
        }

        
        if (signedParts != null) {
            signedParts.serialize(writer);
            
        } else if (signedElements != null) {
            signedElements.serialize(writer);
            
        } else if (encryptedParts != null) {
            encryptedParts.serialize(writer);
            
        } else if (encryptedElements != null) {
            encryptedElements.serialize(writer);
        }
        // </wsp:Policy>
        writer.writeEndElement();

        writer.writeEndElement();
        // </sp:SupportingToken>
    }
}
