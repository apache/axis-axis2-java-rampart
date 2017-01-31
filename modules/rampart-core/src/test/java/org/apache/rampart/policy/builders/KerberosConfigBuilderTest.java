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

import static com.google.common.truth.Truth.assertAbout;
import static org.apache.axiom.truth.xml.XMLTruth.xml;

import java.io.IOException;
import java.io.InputStream;
import java.io.StringWriter;
import java.util.Iterator;
import java.util.List;

import javax.xml.stream.XMLOutputFactory;
import javax.xml.stream.XMLStreamWriter;

import junit.framework.TestCase;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyBuilder;
import org.apache.rampart.policy.RampartPolicyBuilder;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.secpolicy.WSSPolicyException;

public class KerberosConfigBuilderTest extends TestCase {

    public static final String KERBEROS_CONFIG_POLICY_FILE = "kerberosConfig.policy";
    
    private static final Log log = LogFactory.getLog(KerberosConfigBuilderTest.class);
    
    public void testBuildKerberosConfig() throws WSSPolicyException {
        Policy kerberosConfigPolicy = loadKerberosConfigPolicy();
        assertNotNull(String.format("Failed to parse policy file: %s", KERBEROS_CONFIG_POLICY_FILE), kerberosConfigPolicy);
        
        Iterator<List<Assertion>> iter = kerberosConfigPolicy.getAlternatives();
         
        assertTrue(String.format("No policy alternatives found in policy file: %s", KERBEROS_CONFIG_POLICY_FILE), iter.hasNext());
         
         //Process policy and build policy data
        RampartPolicyData policyData = RampartPolicyBuilder.build(iter.next());

        RampartConfig rampartConfig = policyData.getRampartConfig();
        assertNotNull(String.format("No rampartConfig found in policy file: %s", KERBEROS_CONFIG_POLICY_FILE), rampartConfig);
        KerberosConfig kerberosConfig = rampartConfig.getKerberosConfig();
        assertNotNull(String.format("No kerberosConfig found in policy file: %s", KERBEROS_CONFIG_POLICY_FILE), kerberosConfig);
        
        assertEquals("Kerberos jaas context name not configured as expected.", "alice", kerberosConfig.getJaasContext());
        assertEquals("Kerberos principal name not configured as expected.", "alice", kerberosConfig.getPrincipalName());
        assertEquals("Kerberos principal password not configured as expected.", "changeit", kerberosConfig.getPrincipalPassword());
        assertEquals("Kerberos service principal name not configured as expected.", "bob/example.com", kerberosConfig.getServicePrincipalName());
        assertEquals("Kerberos token decoder class not configured as expected.", "org.foo.KerberosTokenDecoderImpl", kerberosConfig.getKerberosTokenDecoderClass());
        assertTrue("Request for Kerberos credential delegation is expected to be enabled.", kerberosConfig.isRequstCredentialDelegation());
    }

    public void testSerializeKerberosConfig() throws Exception {
        Policy kerberosConfigPolicy = loadKerberosConfigPolicy();
        assertNotNull(String.format("Failed to parse policy file: %s", KERBEROS_CONFIG_POLICY_FILE), kerberosConfigPolicy);
        
        //serialize the kerberos config policy
        StringWriter writer = new StringWriter();
        XMLStreamWriter streamWriter = null;
        try {
            streamWriter = XMLOutputFactory.newInstance().createXMLStreamWriter(writer);
            kerberosConfigPolicy.serialize(streamWriter);
        }
        finally {
            if (streamWriter != null) {
                streamWriter.close();
            }
        }
        
        assertAbout(xml())
                .that(writer.toString())
                .ignoringWhitespace()
                .hasSameContentAs(KerberosConfigBuilderTest.class.getResource(KERBEROS_CONFIG_POLICY_FILE));
    }

    private Policy loadKerberosConfigPolicy() {
        InputStream kerberosConfigStream = null;
        try {
            kerberosConfigStream = this.getClass().getResourceAsStream(KERBEROS_CONFIG_POLICY_FILE);
            PolicyBuilder builder = new PolicyBuilder();
            return builder.getPolicy(kerberosConfigStream);
        }
        finally {
            closeStream(kerberosConfigStream);
        }
    }
    
    private void closeStream(InputStream in) {
        if (in != null) {
            try {
                in.close();
            }
            catch (IOException e) {
                log.error("Failed to close input stream.", e);
            }
        }
    }
}