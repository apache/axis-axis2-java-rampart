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
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class Wss10 extends AbstractSecurityAssertion {
    
    private boolean mustSupportRefKeyIdentifier;
    private boolean MustSupportRefIssuerSerial;
    private boolean MustSupportRefExternalURI;
    private boolean MustSupportRefEmbeddedToken;
    
    public Wss10(int version) {
        setVersion(version);
    }
    
    /**
     * @return Returns the mustSupportRefEmbeddedToken.
     */
    public boolean isMustSupportRefEmbeddedToken() {
        return MustSupportRefEmbeddedToken;
    }
    /**
     * @param mustSupportRefEmbeddedToken The mustSupportRefEmbeddedToken to set.
     */
    public void setMustSupportRefEmbeddedToken(boolean mustSupportRefEmbeddedToken) {
        MustSupportRefEmbeddedToken = mustSupportRefEmbeddedToken;
    }
    /**
     * @return Returns the mustSupportRefExternalURI.
     */
    public boolean isMustSupportRefExternalURI() {
        return MustSupportRefExternalURI;
    }
    /**
     * @param mustSupportRefExternalURI The mustSupportRefExternalURI to set.
     */
    public void setMustSupportRefExternalURI(boolean mustSupportRefExternalURI) {
        MustSupportRefExternalURI = mustSupportRefExternalURI;
    }
    /**
     * @return Returns the mustSupportRefIssuerSerial.
     */
    public boolean isMustSupportRefIssuerSerial() {
        return MustSupportRefIssuerSerial;
    }
    /**
     * @param mustSupportRefIssuerSerial The mustSupportRefIssuerSerial to set.
     */
    public void setMustSupportRefIssuerSerial(boolean mustSupportRefIssuerSerial) {
        MustSupportRefIssuerSerial = mustSupportRefIssuerSerial;
    }
    /**
     * @return Returns the mustSupportRefKeyIdentifier.
     */
    public boolean isMustSupportRefKeyIdentifier() {
        return mustSupportRefKeyIdentifier;
    }
    /**
     * @param mustSupportRefKeyIdentifier The mustSupportRefKeyIdentifier to set.
     */
    public void setMustSupportRefKeyIdentifier(boolean mustSupportRefKeyIdentifier) {
        this.mustSupportRefKeyIdentifier = mustSupportRefKeyIdentifier;
    }
    
    public QName getName() {
        if ( version == SPConstants.SP_V12 ) {
            return SP12Constants.WSS10;
        } else {
            return SP11Constants.WSS10;
        }  
    }
    
    public PolicyComponent normalize() {
        return this;
    }
    
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = getName().getPrefix();
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        // <sp:Wss10>
        writeStartElement(writer, prefix, localname, namespaceURI);
        
        // <wsp:Policy>
        writeStartElement(writer, SPConstants.POLICY);
        
        if (isMustSupportRefKeyIdentifier()) {
            // <sp:MustSupportRefKeyIdentifier />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_KEY_IDENTIFIER, namespaceURI);
        }
        
        if (isMustSupportRefIssuerSerial()) {
            // <sp:MustSupportRefIssuerSerial />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_ISSUER_SERIAL, namespaceURI);
        }
        
        if (isMustSupportRefExternalURI()) {
            // <sp:MustSupportRefExternalURI />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_EXTERNAL_URI, namespaceURI);
        }
        
        if (isMustSupportRefEmbeddedToken()) {
            // <sp:MustSupportRefEmbeddedToken />
            writeEmptyElement(writer, prefix, SPConstants.MUST_SUPPORT_REF_EMBEDDED_TOKEN, namespaceURI);
        }
        
        // </wsp:Policy>
        writer.writeEndElement();
        
        // </sp:Wss10>
        writer.writeEndElement();

    }
}
