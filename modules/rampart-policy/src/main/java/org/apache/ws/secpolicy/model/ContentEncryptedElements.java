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
import java.util.HashMap;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.PolicyComponent;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class ContentEncryptedElements extends AbstractSecurityAssertion {

    private ArrayList<String> xPathExpressions = new ArrayList<String>();
    
    private HashMap<String, String> declaredNamespaces = new HashMap<String, String>();

    private String xPathVersion;

    public ContentEncryptedElements(int version) {
        setVersion(version);
    }

    /**
     * @return Returns the xPathExpressions.
     */
    public ArrayList<String> getXPathExpressions() {
        return xPathExpressions;
    }

    public void addXPathExpression(String expr) {
        this.xPathExpressions.add(expr);
    }

    /**
     * @return Returns the xPathVersion.
     */
    public String getXPathVersion() {
        return xPathVersion;
    }

    /**
     * @param pathVersion
     *            The xPathVersion to set.
     */
    public void setXPathVersion(String pathVersion) {
        xPathVersion = pathVersion;
    }
    
    public HashMap<String, String> getDeclaredNamespaces () {
        return declaredNamespaces;
    }
    
    public void addDeclaredNamespaces(String uri, String prefix ) {
        declaredNamespaces.put(prefix, uri);
    }
        
    public void serialize(XMLStreamWriter writer) throws XMLStreamException {

        String prefix = getName().getPrefix();
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        //  <sp:ContentEncryptedElements>
        writeStartElement(writer, prefix, localName, namespaceURI);
        
        if (xPathVersion != null) {
            writeAttribute(writer, prefix, namespaceURI, SPConstants.XPATH_VERSION, xPathVersion);
        }

        String xpathExpression;

        for (Iterator<String> iterator = xPathExpressions.iterator(); iterator
                .hasNext();) {
            xpathExpression = iterator.next();
            // <sp:XPath ..>
            writeStartElement(writer, prefix, SPConstants.XPATH_EXPR, namespaceURI);
            writer.writeCharacters(xpathExpression);
            writer.writeEndElement();
        }

        //</sp:ContentEncryptedElements>
        writer.writeEndElement();
    }

    public QName getName() {
        return SP12Constants.CONTENT_ENCRYPTED_ELEMENTS;
    }

    public PolicyComponent normalize() {
        return this;
    }
}
