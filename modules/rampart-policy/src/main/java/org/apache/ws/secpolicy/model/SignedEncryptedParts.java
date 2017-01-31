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

public class SignedEncryptedParts extends AbstractSecurityAssertion {

    private boolean body;
    
    private boolean attachments;
    
    private ArrayList<Header> headers = new ArrayList<Header>();
    
    private boolean signedParts;

    private boolean signAllHeaders;

    public boolean isSignAllHeaders() {
        return signAllHeaders;
    }

    public void setSignAllHeaders(boolean signAllHeaders) {
        this.signAllHeaders = signAllHeaders;
    }
    
    public SignedEncryptedParts(boolean signedParts, int version) {
        this.signedParts = signedParts;
        setVersion(version);
    }

    /**
     * @return Returns the body.
     */
    public boolean isBody() {
        return body;
    }

    /**
     * @param body The body to set.
     */
    public void setBody(boolean body) {
        this.body = body;
    }
    
    /**
     * @return Returns the attachments.
     */
    public boolean isAttachments() {
        return attachments;
    }

    /**
     * @param attachments The attachments to set.
     */
    public void setAttachments(boolean attachments) {
        this.attachments = attachments;
    }

    /**
     * @return Returns the headers.
     */
    public ArrayList<Header> getHeaders() {
        return this.headers;
    }

    /**
     * @param headers The headers to set.
     */
    public void addHeader(Header header) {
        this.headers.add(header);
    }

    /**
     * @return Returns the signedParts.
     */
    public boolean isSignedParts() {
        return signedParts;
    }

    public QName getName() {
        if (signedParts) {
            if ( version == SPConstants.SP_V12) {
                return SP12Constants.SIGNED_PARTS;
            } else {
                return SP11Constants.SIGNED_PARTS;
            }           
        }
        
        if ( version == SPConstants.SP_V12) {
            return SP12Constants.ENCRYPTED_PARTS;
        } else {
            return SP11Constants.ENCRYPTED_PARTS;
        }
        
    }

    public PolicyComponent normalize() {
        return this;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = getName().getPrefix();
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();
            
        // <sp:SignedParts> | <sp:EncryptedParts> 
        writeStartElement(writer, prefix, localName, namespaceURI);
        
        if (isBody()) {
            // <sp:Body />
            writeEmptyElement(writer, prefix, SPConstants.BODY, namespaceURI);
        }
        
        Header header;        
        for (Iterator<Header> iterator = headers.iterator(); iterator.hasNext();) {
            header = iterator.next();
            // <sp:Header Name=".." Namespace=".." />
            writeStartElement(writer, prefix, SPConstants.HEADER, namespaceURI);
            // Name attribute is optional
            if (header.getName() != null) {
                writer.writeAttribute("Name", header.getName());
            }
            writer.writeAttribute("Namespace", header.getNamespace());
            
            writer.writeEndElement();
        }
        
        if (isAttachments() && version == SPConstants.SP_V12) {
            // <sp:Attachments />
            writeEmptyElement(writer, prefix, SPConstants.ATTACHMENTS, namespaceURI);
        }
        
        // </sp:SignedParts> | </sp:EncryptedParts>
        writer.writeEndElement();
    }    
    
    
}
