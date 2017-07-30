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
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class RequiredParts extends AbstractSecurityAssertion {
    
    private ArrayList<Header> headers = new ArrayList<Header>();
    
    public RequiredParts(int version) {
        setVersion(version);
    }

    /**
     * @return Returns the headers.
     */
    public ArrayList<Header> getHeaders() {
        return this.headers;
    }

    /**
     * @param header The header to set.
     */
    public void addHeader(Header header) {
        this.headers.add(header);
    }


    public QName getName() {
         return SP12Constants.REQUIRED_PARTS;         
    }

    public PolicyComponent normalize() {
        return this;
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = getName().getPrefix();
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        // <sp:RequiredParts> 
        writeStartElement(writer, prefix, localName, namespaceURI);
        
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
        
        // </sp:RequiredParts>
        writer.writeEndElement();
    }    
    
    
}
