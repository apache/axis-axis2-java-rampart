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

import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class Wss11 extends Wss10 {
    
    private boolean MustSupportRefThumbprint;
    private boolean MustSupportRefEncryptedKey;
    private boolean RequireSignatureConfirmation;
    
    public Wss11(int version) {
        super(version);
    }
    
    /**
     * @return Returns the mustSupportRefEncryptedKey.
     */
    public boolean isMustSupportRefEncryptedKey() {
        return MustSupportRefEncryptedKey;
    }
    /**
     * @param mustSupportRefEncryptedKey The mustSupportRefEncryptedKey to set.
     */
    public void setMustSupportRefEncryptedKey(boolean mustSupportRefEncryptedKey) {
        MustSupportRefEncryptedKey = mustSupportRefEncryptedKey;
    }
    /**
     * @return Returns the mustSupportRefThumbprint.
     */
    public boolean isMustSupportRefThumbprint() {
        return MustSupportRefThumbprint;
    }
    /**
     * @param mustSupportRefThumbprint The mustSupportRefThumbprint to set.
     */
    public void setMustSupportRefThumbprint(boolean mustSupportRefThumbprint) {
        MustSupportRefThumbprint = mustSupportRefThumbprint;
    }
    /**
     * @return Returns the requireSignatureConfirmation.
     */
    public boolean isRequireSignatureConfirmation() {
        return RequireSignatureConfirmation;
    }
    /**
     * @param requireSignatureConfirmation The requireSignatureConfirmation to set.
     */
    public void setRequireSignatureConfirmation(boolean requireSignatureConfirmation) {
        RequireSignatureConfirmation = requireSignatureConfirmation;
    }
    
    public QName getName() {
        if ( version == SPConstants.SP_V12 ) {
            return SP12Constants.WSS11;
        } else {
            return SP11Constants.WSS11;
        }  
    }
    
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = getName().getPrefix();
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        // <sp:Wss11>
        writeStartElement(writer, prefix, localname, namespaceURI);
        
        // <wsp:Policy>
        writeStartElement(writer, SPConstants.POLICY);
        
        // <sp:MustSupportRefKeyIndentifier />
        if (isMustSupportRefKeyIdentifier()) {
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_KEY_IDENTIFIER , namespaceURI);
        }
        
        if (isMustSupportRefIssuerSerial()) {
            // <sp:MustSupportRefIssuerSerial />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_ISSUER_SERIAL , namespaceURI);
        }
        
        if (isMustSupportRefExternalURI()) {
            // <sp:MustSupportRefExternalURI />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_EXTERNAL_URI , namespaceURI);
        }
        
        if (isMustSupportRefEmbeddedToken()) {
            // <sp:MustSupportRefEmbeddedToken />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_EMBEDDED_TOKEN , namespaceURI);
        }
        
        if (isMustSupportRefThumbprint()) {
            // <sp:MustSupportRefThumbprint />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_THUMBPRINT , namespaceURI);
        }
        
        if (isMustSupportRefEncryptedKey()) {
            // <sp:MustSupportRefEncryptedKey />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_ENCRYPTED_KEY , namespaceURI);
        }
        
        if (isRequireSignatureConfirmation()) {
            // <sp:RequireSignatureConfirmation />
            writeEmptyElement(writer, prefix, SPConstants.REQUIRE_SIGNATURE_CONFIRMATION , namespaceURI);
        }
        
        // </wsp:Policy>
        writer.writeEndElement();
        
        // </sp:Wss11>
        writer.writeEndElement();
    }
}
