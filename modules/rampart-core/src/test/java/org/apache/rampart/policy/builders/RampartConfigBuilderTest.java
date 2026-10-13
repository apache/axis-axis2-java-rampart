/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.rampart.policy.builders;

import java.io.StringWriter;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import junit.framework.TestCase;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.rampart.policy.model.RampartConfig;

public class RampartConfigBuilderTest extends TestCase {

    private static final String VALIDATOR = "org.example.LdapUsernameTokenValidator";

    private static RampartConfig build(String body) throws Exception {
        OMElement element = AXIOMUtil.stringToOM(
                "<ramp:RampartConfig xmlns:ramp=\"" + RampartConfig.NS + "\">" + body
                        + "</ramp:RampartConfig>");
        return (RampartConfig) new RampartConfigBuilder().build(element, null);
    }

    /** RAMPART-460: usernameTokenValidatorClass is parsed and written back out. */
    public void testUsernameTokenValidatorClassRoundTrip() throws Exception {
        RampartConfig config = build("<ramp:usernameTokenValidatorClass>\n    " + VALIDATOR
                + "\n</ramp:usernameTokenValidatorClass>");
        assertEquals(VALIDATOR, config.getUsernameTokenValidatorClass());

        StringWriter out = new StringWriter();
        XMLStreamWriter writer = XMLOutputFactory.newInstance().createXMLStreamWriter(out);
        config.serialize(writer);
        writer.flush();

        assertEquals(VALIDATOR, build(stripRoot(out.toString())).getUsernameTokenValidatorClass());
    }

    public void testUsernameTokenValidatorClassAbsentByDefault() throws Exception {
        assertNull(build("").getUsernameTokenValidatorClass());
    }

    /** An empty element means the default validator and is not written back out. */
    public void testEmptyUsernameTokenValidatorClassNotSerialized() throws Exception {
        RampartConfig config = build("<ramp:usernameTokenValidatorClass/>");
        assertEquals("", config.getUsernameTokenValidatorClass());

        StringWriter out = new StringWriter();
        XMLStreamWriter writer = XMLOutputFactory.newInstance().createXMLStreamWriter(out);
        config.serialize(writer);
        writer.flush();

        assertFalse(out.toString().contains(RampartConfig.USERNAME_TOKEN_VALIDATOR_CLASS_LN));
    }

    private static String stripRoot(String xml) throws Exception {
        OMElement root = AXIOMUtil.stringToOM(xml);
        StringBuilder sb = new StringBuilder();
        for (java.util.Iterator<OMElement> it = root.getChildElements(); it.hasNext();) {
            sb.append(it.next().toString());
        }
        return sb.toString();
    }
}
