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
import org.apache.ws.secpolicy.Constants;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class X509Token extends Token {

    private boolean requireKeyIdentifierReference;
    
    private boolean requireIssuerSerialReference;
    
    private boolean requireEmbeddedTokenReference;
    
    private boolean requireThumbprintReference;
    
    private boolean requireX509V3KeyIdentifierReference;
    
    private String tokenVersionAndType = Constants.WSS_X509_V3_TOKEN10;
    
    private String encryptionUser;

    private String userCertAlias;

    public String getEncryptionUser() {
        return encryptionUser;
    }

    public void setEncryptionUser(String encryptionUser) {
        this.encryptionUser = encryptionUser;
    }

    public String getUserCertAlias() {
        return userCertAlias;
    }

    public void setUserCertAlias(String userCertAlias) {
        this.userCertAlias = userCertAlias;
    }
    
    public X509Token(int version) {
        setVersion(version);
    }
    
    /**
     * @return Returns the requireEmbeddedTokenReference.
     */
    public boolean isRequireEmbeddedTokenReference() {
        return requireEmbeddedTokenReference;
    }

    /**
     * @param requireEmbeddedTokenReference The requireEmbeddedTokenReference to set.
     */
    public void setRequireEmbeddedTokenReference(
            boolean requireEmbeddedTokenReference) {
        this.requireEmbeddedTokenReference = requireEmbeddedTokenReference;
    }

    /**
     * @return Returns the requireIssuerSerialReference.
     */
    public boolean isRequireIssuerSerialReference() {
        return requireIssuerSerialReference;
    }

    /**
     * @param requireIssuerSerialReference The requireIssuerSerialReference to set.
     */
    public void setRequireIssuerSerialReference(boolean requireIssuerSerialReference) {
        this.requireIssuerSerialReference = requireIssuerSerialReference;
    }

    /**
     * @return Returns the requireKeyIdentifierReference.
     */
    public boolean isRequireKeyIdentifierReference() {
        return requireKeyIdentifierReference;
    }

    /**
     * @param requireKeyIdentifierReference The requireKeyIdentifierReference to set.
     */
    public void setRequireKeyIdentifierReference(
            boolean requireKeyIdentifierReference) {
        this.requireKeyIdentifierReference = requireKeyIdentifierReference;
    }

    /**
     * @return Returns the requireThumbprintReference.
     */
    public boolean isRequireThumbprintReference() {
        return requireThumbprintReference;
    }

    /**
     * @param requireThumbprintReference The requireThumbprintReference to set.
     */
    public void setRequireThumbprintReference(boolean requireThumbprintReference) {
        this.requireThumbprintReference = requireThumbprintReference;
    }

    /**
     * @return Returns the requireX509V3KeyIdentifierReference
     */
    public boolean isRequireX509V3KeyIdentifierReference() {
        return requireX509V3KeyIdentifierReference;
    }
    
    /**
     * @param requireX509V3KeyIdentifierReference The requireX509V3KeyIdentifierReference to set
     */
    public void setRequireX509V3KeyIdentifierReference(boolean requireX509V3KeyIdentifierReference) {
        this.requireX509V3KeyIdentifierReference = requireX509V3KeyIdentifierReference;
    }
    
    /**
     * @return Returns the tokenVersionAndType.
     */
    public String getTokenVersionAndType() {
        return tokenVersionAndType;
    }

    /**
     * @param tokenVersionAndType The tokenVersionAndType to set.
     */
    public void setTokenVersionAndType(String tokenVersionAndType) {
        this.tokenVersionAndType = tokenVersionAndType;
    }

    public QName getName() {
        if ( version == SPConstants.SP_V12) {
            return SP12Constants.X509_TOKEN;
        } else {
            return SP11Constants.X509_TOKEN;
        }      
    }

    public PolicyComponent normalize() {
        throw new UnsupportedOperationException();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = getName().getPrefix();
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        // <sp:X509Token> 
        writeStartElement(writer, prefix, localName, namespaceURI);
        
        String inclusion;
        
        if (version == SPConstants.SP_V12) {
            inclusion = SP12Constants.getAttributeValueFromInclusion(getInclusion());
        } else {
            inclusion = SP11Constants.getAttributeValueFromInclusion(getInclusion()); 
        }
        
        if (inclusion != null) {
            writeAttribute(writer, prefix, namespaceURI, SPConstants.ATTR_INCLUDE_TOKEN , inclusion);
        }
        
        // <wsp:Policy>
        writeStartElement(writer, SPConstants.POLICY);
        
        if (isRequireKeyIdentifierReference() || isRequireX509V3KeyIdentifierReference()) {
            // <sp:RequireKeyIdentifierReference />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_KEY_IDENTIFIRE_REFERENCE, namespaceURI);
        }
        
        if (isRequireIssuerSerialReference()) {
            // <sp:RequireIssuerSerialReference />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_ISSUER_SERIAL_REFERENCE, namespaceURI);
        }
        
        if (isRequireEmbeddedTokenReference()) {
            // <sp:RequireEmbeddedTokenReference />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_EMBEDDED_TOKEN_REFERENCE, namespaceURI);
        }
        
        if (isRequireThumbprintReference()) {
            // <sp:RequireThumbprintReference />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_THUMBPRINT_REFERENCE, namespaceURI);
        }
        
        if (tokenVersionAndType != null) {
            // <sp:WssX509V1Token10 /> | ..
            writeEmptyElement(writer, prefix, tokenVersionAndType, namespaceURI);
        }
        
        if(isDerivedKeys()) {
            // <sp:RequireDerivedKeys/>
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_DERIVED_KEYS, namespaceURI);
        }
        
        // </wsp:Policy>
        writer.writeEndElement();
        
        // </sp:X509Token>
        writer.writeEndElement();
    }
       
}
