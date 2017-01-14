/*
 * Copyright 2001-2014 The Apache Software Foundation.
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

import org.apache.ws.secpolicy.Constants;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;
import org.apache.ws.secpolicy.SPConstants;

public class KerberosToken extends Token {

    private boolean requiresKerberosV5Token;

    private boolean requiresGssKerberosV5Token;

    private boolean requiresKeyIdentifierReference;

    private String tokenVersionAndType = Constants.WSS_KERBEROS_TOKEN11;

    public String getTokenVersionAndType() {
        return tokenVersionAndType;
    }

    public void setTokenVersionAndType(String tokenVersionAndType) {
        this.tokenVersionAndType = tokenVersionAndType;
    }

    public boolean isRequiresKerberosV5Token() {
        return requiresKerberosV5Token;
    }

    public void setRequiresKerberosV5Token(boolean requiresKerberosV5Token) {
        this.requiresKerberosV5Token = requiresKerberosV5Token;
    }

    public boolean isRequiresGssKerberosV5Token() {
        return requiresGssKerberosV5Token;
    }

    public void setRequiresGssKerberosV5Token(boolean requiresGssKerberosV5Token) {
        this.requiresGssKerberosV5Token = requiresGssKerberosV5Token;
    }

    public boolean isRequiresKeyIdentifierReference() {
        return requiresKeyIdentifierReference;
    }

    public void setRequiresKeyIdentifierReference(boolean
        requiresKeyIdentifierReference) {
        this.requiresKeyIdentifierReference = requiresKeyIdentifierReference;
    }

    public KerberosToken(int version) {
        setVersion(version);
    }

    public QName getName() {
        if (version == SPConstants.SP_V12) {
            return SP12Constants.KERBEROS_TOKEN;
        } 
        else {
            return SP11Constants.KERBEROS_TOKEN;
        }
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String localName = getName().getLocalPart();
        String namespaceURI = getName().getNamespaceURI();

        String prefix = writer.getPrefix(namespaceURI);

        if (prefix == null) {
            prefix = getName().getPrefix();
            writer.setPrefix(prefix, namespaceURI);
        }

        // <sp:KerberosToken>
        writer.writeStartElement(prefix, localName, namespaceURI);

        String inclusion;

        if (version == SPConstants.SP_V12) {
            inclusion = SP12Constants.getAttributeValueFromInclusion(getInclusion());
        } else {
            inclusion = SP11Constants.getAttributeValueFromInclusion(getInclusion());
        }

        if (inclusion != null) {
            writer.writeAttribute(prefix, namespaceURI,
                                  SPConstants.ATTR_INCLUDE_TOKEN, inclusion);
        }

        String pPrefix = writer.getPrefix(SPConstants.POLICY.getNamespaceURI());
        if (pPrefix == null) {
            pPrefix = SPConstants.POLICY.getPrefix();
            writer.setPrefix(pPrefix, SPConstants.POLICY.getNamespaceURI());
        }

        // <wsp:Policy>
        writer.writeStartElement(pPrefix, SPConstants.POLICY.getLocalPart(),
                                 SPConstants.POLICY.getNamespaceURI());

        if (isRequiresKerberosV5Token()) {
            // <sp:WssKerberosV5ApReqToken11 />
            writer.writeStartElement(prefix,SPConstants.REQUIRE_KERBEROS_V5_TOKEN_11,
                                     namespaceURI);
            writer.writeEndElement();
        }

        if (isRequiresGssKerberosV5Token()) {
            // <sp:WssGssKerberosV5ApReqToken11 ... />
            writer.writeStartElement(prefix,
                                     SPConstants.REQUIRE_KERBEROS_GSS_V5_TOKEN_11,
                                     namespaceURI);
            writer.writeEndElement();
        }

        if (isRequiresKeyIdentifierReference()) {
            // <sp:RequireKeyIdentifierReference />
            writer.writeStartElement(prefix,
                                     SPConstants.REQUIRE_KEY_IDENTIFIRE_REFERENCE,
                                     namespaceURI);
            writer.writeEndElement();
        }

        // </wsp:Policy>
        writer.writeEndElement();

        // </sp:KerberosToken>
        writer.writeEndElement();
    }
}
