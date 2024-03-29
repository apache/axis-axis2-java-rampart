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

import java.util.Iterator;
import java.util.List;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.All;
import org.apache.neethi.Assertion;
import org.apache.neethi.ExactlyOne;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.WSSPolicyException;

public class SymmetricBinding extends SymmetricAsymmetricBindingBase {

    private EncryptionToken encryptionToken;
    
    private SignatureToken signatureToken;
    
    private ProtectionToken protectionToken;
    
    public SymmetricBinding(int version) {
        super(version);
    }
    
    /**
     * @return Returns the encryptionToken.
     */
    public EncryptionToken getEncryptionToken() {
        return encryptionToken;
    }

    /**
     * @param encryptionToken The encryptionToken to set.
     * @throws WSSPolicyException If an error occurred setting the EncryptionToken
     */
    public void setEncryptionToken(EncryptionToken encryptionToken) 
    		throws WSSPolicyException  {
        if(this.protectionToken != null) {
            throw new WSSPolicyException("Cannot use an EncryptionToken in a " +
                    "SymmetricBinding when there is a ProtectionToken");
        }
        this.encryptionToken = encryptionToken;
    }

    /**
     * @return Returns the protectionToken.
     */
    public ProtectionToken getProtectionToken() {
        return protectionToken;
    }

    /**
     * @param protectionToken The protectionToken to set.
     * @throws WSSPolicyException If an error occurred setting the ProtectionToken
     */
    public void setProtectionToken(ProtectionToken protectionToken) 
    		throws WSSPolicyException  {
        if(this.encryptionToken != null || this.signatureToken != null) {
            throw new WSSPolicyException("Cannot use a ProtectionToken in a " +
            "SymmetricBinding when there is a SignatureToken or an" +
            "EncryptionToken");
        }
        this.protectionToken = protectionToken;
    }

    /**
     * @return Returns the signatureToken.
     */
    public SignatureToken getSignatureToken() {
        return signatureToken;
    }

    /**
     * @param signatureToken The signatureToken to set.
     * @throws WSSPolicyException If an error occurred getting the SignatureToken
     */
    public void setSignatureToken(SignatureToken signatureToken) 
    		throws WSSPolicyException {
        if(this.protectionToken != null) {
            throw new WSSPolicyException("Cannot use a SignatureToken in a " +
                    "SymmetricBinding when there is a ProtectionToken");
        }
        this.signatureToken = signatureToken;
    }
    
    public QName getName() {
        if ( version == SPConstants.SP_V12) {
            return SP12Constants.SYMMETRIC_BINDING;
        } else {
            return SP11Constants.SYMMETRIC_BINDING;
        }
        
    }

    public PolicyComponent normalize() {
        if (isNormalized()) {
            return this;
        }
        
        AlgorithmSuite algorithmSuite = getAlgorithmSuite();
        List<Assertion> configurations = algorithmSuite.getConfigurations();
        
        Policy policy = new Policy();
        ExactlyOne exactlyOne = new ExactlyOne();
        
        All wrapper;
        SymmetricBinding symmetricBinding;
        
        try {
	        for (Iterator<Assertion> iterator = configurations.iterator(); iterator.hasNext();) {
	            wrapper = new All();
	            symmetricBinding = new SymmetricBinding(this.version);
	            
	            algorithmSuite = (AlgorithmSuite) iterator.next();
	            symmetricBinding.setAlgorithmSuite(algorithmSuite);
	            
	            symmetricBinding.setEncryptionToken(getEncryptionToken());
	            symmetricBinding.setEntireHeadersAndBodySignatures(isEntireHeadersAndBodySignatures());
	            symmetricBinding.setIncludeTimestamp(isIncludeTimestamp());
	            symmetricBinding.setLayout(getLayout());
	            symmetricBinding.setProtectionOrder(getProtectionOrder());
	            symmetricBinding.setProtectionToken(getProtectionToken());
	            symmetricBinding.setSignatureProtection(isSignatureProtection());
	            symmetricBinding.setSignatureToken(getSignatureToken());
	            symmetricBinding.setSignedEndorsingSupportingTokens(getSignedEndorsingSupportingTokens());
	            symmetricBinding.setSignedSupportingToken(getSignedSupportingToken());
	            symmetricBinding.setTokenProtection(isTokenProtection());
	            
	            symmetricBinding.setNormalized(true);
	            wrapper.addPolicyComponent(symmetricBinding);
	            exactlyOne.addPolicyComponent(wrapper);
	        }
        } catch (WSSPolicyException e) {
        	throw new IllegalArgumentException(e);
        }
        policy.addPolicyComponent(exactlyOne);
        return policy;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        
        String prefix = getName().getPrefix();
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();
        
        // <sp:SymmetricBinding>
        writeStartElement(writer, prefix, localname, namespaceURI);
        
        // <wsp:Policy>
        writeStartElement(writer, SPConstants.POLICY);
        
        if (encryptionToken != null) {
            encryptionToken.serialize(writer);
            
        } else if ( protectionToken != null) {
            protectionToken.serialize(writer);
            
        } else {
            throw new RuntimeException("Either EncryptionToken or ProtectionToken must be set");
        }
        
        AlgorithmSuite algorithmSuite = getAlgorithmSuite();
        
        if (algorithmSuite == null) {
            throw new RuntimeException("AlgorithmSuite must be set");
        }
        // <sp:AlgorithmSuite />
        algorithmSuite.serialize(writer);
        
        Layout layout = getLayout();
        if (layout != null) {
            // <sp:Layout />
            layout.serialize(writer);
        }
        
        if (isIncludeTimestamp()) {
            // <sp:IncludeTimestamp />
            writeEmptyElement(writer, prefix, SPConstants.INCLUDE_TIMESTAMP, namespaceURI);
        }
        
        if (SPConstants.ENCRYPT_BEFORE_SIGNING.equals(getProtectionOrder())) {
            // <sp:EncryptBeforeSigning />
            writeEmptyElement(writer, prefix, SPConstants.ENCRYPT_BEFORE_SIGNING, namespaceURI);
        }
        
        if (isSignatureProtection()) {
            // <sp:EncryptSignature />
            writeEmptyElement(writer, prefix, SPConstants.ENCRYPT_SIGNATURE , namespaceURI);
        }
        
        if(isEntireHeadersAndBodySignatures()) {
            writer.writeEmptyElement(prefix, SPConstants.ONLY_SIGN_ENTIRE_HEADERS_AND_BODY, namespaceURI);
        }
        // </wsp:Policy>
        writer.writeEndElement();
        
        // </sp:SymmetricBinding>
        writer.writeEndElement();
        
    }
}
