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

package org.apache.rahas.impl.util;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.dom.DOMMetaFactory;
import org.apache.rahas.TrustException;
import org.w3c.dom.Document;

import javax.xml.parsers.DocumentBuilderFactory;
import javax.xml.parsers.ParserConfigurationException;

import static org.apache.axiom.om.OMAbstractFactory.FEATURE_DOM;

/**
 * This class implements some utility methods common to SAML1 and SAML2.
 */
public class CommonUtil {

    /**
     * This method creates a DOM compatible Axiom document.
     * @return DOM compatible Axiom document
     * @throws TrustException If an error occurred while creating the Document.
     */
    public static Document getOMDOMDocument() throws TrustException {
        DOMMetaFactory metaFactory = (DOMMetaFactory) OMAbstractFactory.getMetaFactory(FEATURE_DOM);
            DocumentBuilderFactory dbf = metaFactory.newDocumentBuilderFactory();
        try {
            return  dbf.newDocumentBuilder().newDocument();
        } catch (ParserConfigurationException e) {
            throw new TrustException("Error creating Axiom compatible DOM Document", e);
        }
    }
}
