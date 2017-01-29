/*
*  Copyright (c) 2005-2010, WSO2 Inc. (http://www.wso2.org) All Rights Reserved.
*
*  WSO2 Inc. licenses this file to you under the Apache License,
*  Version 2.0 (the "License"); you may not use this file except
*  in compliance with the License.
*  You may obtain a copy of the License at
*
*    http://www.apache.org/licenses/LICENSE-2.0
*
* Unless required by applicable law or agreed to in writing,
* software distributed under the License is distributed on an
* "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
* KIND, either express or implied.  See the License for the
* specific language governing permissions and limitations
* under the License.
*/

package org.apache.rahas.test.util;

import junit.framework.TestCase;
import org.apache.axiom.om.OMElement;
import org.apache.rahas.Rahas;
import org.apache.ws.security.WSSConfig;
import org.opensaml.Configuration;
import org.opensaml.xml.io.MarshallerFactory;
import org.w3c.dom.Element;

import javax.xml.transform.OutputKeys;
import javax.xml.transform.Transformer;
import javax.xml.transform.TransformerException;
import javax.xml.transform.TransformerFactory;
import javax.xml.transform.dom.DOMSource;
import javax.xml.transform.stream.StreamResult;
import java.io.StringWriter;

/**
 * An abstract class for tests
 */
public class AbstractTestCase extends TestCase {

    protected static MarshallerFactory marshallerFactory;

    private static final boolean PRINT = false;

    public void setUp() throws Exception {

        Rahas rahas = new Rahas();
        //noinspection NullableProblems
        rahas.init(null, null);

        WSSConfig.init();

        org.apache.xml.security.Init.init();

        marshallerFactory = Configuration.getMarshallerFactory();

    }

    public String getXMLString(Element element) throws TransformerException {

        TransformerFactory transfac = TransformerFactory.newInstance();
        Transformer trans = transfac.newTransformer();
        trans.setOutputProperty(OutputKeys.OMIT_XML_DECLARATION, "yes");
        trans.setOutputProperty(OutputKeys.INDENT, "yes");

        // create string from xml tree
        StringWriter sw = new StringWriter();
        StreamResult result = new StreamResult(sw);
        DOMSource source = new DOMSource(element);
        trans.transform(source, result);
        return sw.toString();

    }

    public void printElement(Element element) throws TransformerException {
        // print xml
        if (PRINT) {
            System.out.println(getXMLString(element));
        }
    }

    public void printElement(OMElement element) throws TransformerException {
        // print xml
        if (PRINT) {
            element.build();
            System.out.println(element.toString());
        }
    }

    public void testDummy() {

    }

}
