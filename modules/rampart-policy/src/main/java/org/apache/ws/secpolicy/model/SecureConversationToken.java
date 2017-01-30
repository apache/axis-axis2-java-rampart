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

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Policy;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

/**
 * Model class of SecureConversationToken assertion
 */
public class SecureConversationToken extends SecurityContextToken {

    private Policy bootstrapPolicy;

    private OMElement issuerEpr;
    
    public SecureConversationToken(int version) {
        super(version);
    }

    /**
     * @return Returns the bootstrapPolicy.
     */
    public Policy getBootstrapPolicy() {
        return bootstrapPolicy;
    }

    /**
     * @param bootstrapPolicy
     *            The bootstrapPolicy to set.
     */
    public void setBootstrapPolicy(Policy bootstrapPolicy) {
        this.bootstrapPolicy = bootstrapPolicy;
    }

    /*
     * (non-Javadoc)
     * 
     * @see org.apache.neethi.Assertion#getName()
     */
    public QName getName() {
        if ( version == SPConstants.SP_V12) {
            return SP12Constants.SECURE_CONVERSATION_TOKEN;
        } else {
            return SP11Constants.SECURE_CONVERSATION_TOKEN; 
        }      
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {

        String prefix = getName().getPrefix();
        String localname = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        // <sp:SecureConversationToken>
        writeStartElement(writer, prefix, localname, namespaceURI);

        String inclusion;
        
        if (version == SPConstants.SP_V12) {
            inclusion = SP12Constants.getAttributeValueFromInclusion(getInclusion());
        } else {
            inclusion = SP11Constants.getAttributeValueFromInclusion(getInclusion()); 
        }

        if (inclusion != null) {
            writeAttribute(writer, prefix, namespaceURI, SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
        }

        if (issuerEpr != null) {
            // <sp:Issuer>
            writeStartElement(writer, prefix, SPConstants.ISSUER , namespaceURI);

            issuerEpr.serialize(writer);

            writer.writeEndElement();
        }

        if (isDerivedKeys() || isRequireExternalUriRef()
                || isSc10SecurityContextToken() || (bootstrapPolicy != null)) {

            // <wsp:Policy>
            writeStartElement(writer, SPConstants.POLICY);

            if (isDerivedKeys()) {
                // <sp:RequireDerivedKeys />
                writeEmptyElement(writer, prefix, SPConstants.REQUIRE_DERIVED_KEYS, namespaceURI);
            }
            
            if (isRequireExternalUriRef()) {
                // <sp:RequireExternalUriReference />
                writeEmptyElement(writer, prefix, SPConstants.REQUIRE_EXTERNAL_URI_REFERNCE, namespaceURI);
            }
            
            if (isSc10SecurityContextToken()) {
                // <sp:SC10SecurityContextToken />
                writeEmptyElement(writer, prefix, SPConstants.SC10_SECURITY_CONTEXT_TOKEN, namespaceURI);
            }
            
            if (bootstrapPolicy != null) {
                // <sp:BootstrapPolicy ..>
                writeStartElement(writer, prefix, SPConstants.BOOTSTRAP_POLICY, namespaceURI);
                bootstrapPolicy.serialize(writer);
                writer.writeEndElement();
            }

            // </wsp:Policy>
            writer.writeEndElement();
        }

        // </sp:SecureConversationToken>
        writer.writeEndElement();
    }

    /**
     * @return Returns the issuerEpr.
     */
    public OMElement getIssuerEpr() {
        return issuerEpr;
    }

    /**
     * @param issuerEpr
     *            The issuerEpr to set.
     */
    public void setIssuerEpr(OMElement issuerEpr) {
        this.issuerEpr = issuerEpr;
    }

}
