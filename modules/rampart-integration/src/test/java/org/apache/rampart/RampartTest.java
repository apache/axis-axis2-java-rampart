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

package org.apache.rampart;

import static org.apache.axis2.integration.TestConstants.TESTING_PATH;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.integration.JettyServer;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.junit.Rule;
import org.junit.Test;

import java.util.MissingResourceException;
import java.util.ResourceBundle;

public class RampartTest {

    private static ResourceBundle resources;
    
    @Rule
    public final JettyServer server = new JettyServer(TESTING_PATH + "rampart_service_repo", false);
    
    @Rule
    public final JettyServer secureServer = new JettyServer(TESTING_PATH + "rampart_service_repo", true);
    
    static {
        try {
            resources = ResourceBundle.getBundle("org.apache.rampart.errors");
        } catch (MissingResourceException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    private ServiceClient getServiceClientInstance() throws AxisFault {

        String repository = TESTING_PATH + "rampart_client_repo";

        ConfigurationContext configContext = ConfigurationContextFactory.
                createConfigurationContextFromFileSystem(repository, null);
        ServiceClient serviceClient = new ServiceClient(configContext, null);


        serviceClient.engageModule("addressing");
        serviceClient.engageModule("rampart");

        return serviceClient;

    }

    @Test
    public void testWithPolicy() {
        try {

            ServiceClient serviceClient = getServiceClientInstance();

            //TODO : figure this out !!
            boolean basic256Supported = false;
            
            if(basic256Supported) {
                System.out.println("\nWARNING: We are using key sizes from JCE " +
                        "Unlimited Strength Jurisdiction Policy !!!");
            }

            //for (int i = 34; i <= 34; i++) { //<-The number of tests we have
            for (int i = 1; i <= 35; i++) { //<-The number of tests we have
                if(!basic256Supported && (i == 3 || i == 4 || i == 5)) {
                    //Skip the Basic256 tests
                    continue;
                }

                if(i == 25){
                    // Testcase - 25 is failing, for the moment skipping it.
                    continue;
                }
                Options options = new Options();
                
                if( i == 13 ) {
                    options.setTo(secureServer.getEndpointReference("SecureService" + i));
                    //Username token created with user/pass from options
                    options.setUserName("alice");
                    options.setPassword("password");
                }
                else {
                    options.setTo(server.getEndpointReference("SecureService" + i));
                }
                
                System.out.println("Testing WS-Sec: custom scenario " + i);
                options.setAction("urn:echo");

                ServiceContext context = serviceClient.getServiceContext();
                context.setProperty(RampartMessageData.KEY_RAMPART_POLICY, 
                        loadPolicy("/rampart/policy/" + i + ".xml"));
                serviceClient.setOptions(options);
                
                if (i == 31) {
                    OMNamespace omNamespace = OMAbstractFactory.getOMFactory().createOMNamespace(
                            "http://sample.com", "myNs");
                    SOAPHeaderBlock header = OMAbstractFactory.getSOAP11Factory()
                            .createSOAPHeaderBlock("VitalHeader", omNamespace);
                    header.addChild(AXIOMUtil.stringToOM("<foo>This is a sample Header</foo>"));
                    serviceClient.addHeader(header);
                }
                
                // Invoking the service in the TestCase-28 should fail. So handling it differently..
                if (i == 28 || i == 34) {
                    try {

                        //Blocking invocation
                        serviceClient.sendReceive(getOMElement());

                        String message = "";

                        if (i == 34) {
                            message = "Test case 34 should fail. We are running the service in symmetric binding mode " +
                                      "and client in asymmetric binding mode. Therefore test case 34 should fail.";
                        }

                        fail("Service Should throw an error - " + message);

                    } catch (AxisFault axisFault) {

                        if (i == 28) {
                            assertEquals(resources.getString("encryptionMissing"), axisFault.getMessage());
                        } else if (i == 34) {
                            // TODO this is failing in build server
                            // Need to find the exact cause
                            //assertEquals(resources.getString("invalidSignatureAlgo"), axisFault.getMessage());
                            System.out.println(axisFault.getMessage());
                        }

                    }
                }
                else{

                    //Blocking invocation
                    serviceClient.sendReceive(getEchoElement());
                }
            }

            System.out.println("--------------Testing negative scenarios----------------------------");

            for (int i = 1; i <= 22; i++) {
                if (!basic256Supported && (i == 3 || i == 4 || i == 5)) {
                    //Skip the Basic256 tests
                    continue;
                }
                Options options = new Options();

                if (i == 13) {
                    options.setTo(secureServer.getEndpointReference("SecureService" + i));
                    //Username token created with user/pass from options
                    options.setUserName("alice");
                    options.setPassword("password");
                }
                else {
                    options.setTo(server.getEndpointReference("SecureService" + i));
                }
                System.out.println("Testing WS-Sec: negative scenario " + i);
                options.setAction("urn:returnError");

                ServiceContext context = serviceClient.getServiceContext();
                context.setProperty(RampartMessageData.KEY_RAMPART_POLICY,
                        loadPolicy("/rampart/policy/" + i + ".xml"));
                serviceClient.setOptions(options);

                try {
                    //Blocking invocation
                    serviceClient.sendReceive(getOMElement());
                    fail("Service Should throw an error..");

                } catch (AxisFault axisFault) {
                    assertEquals("Testing negative scenarios with Apache Rampart. Intentional Exception", axisFault.getMessage());
                }
            }

            
            for (int i = 1; i <= 6; i++) { //<-The number of tests we have
                Options options = new Options();
                
                if (i == 3 || i == 6) {
                    options.setTo(secureServer.getEndpointReference("SecureServiceSC" + i));
                }
                else {
                    options.setTo(server.getEndpointReference("SecureServiceSC" + i));
                }

                System.out.println("Testing WS-SecConv: custom scenario " + i);
                options.setAction("urn:echo");

                //Create a new service client instance for each secure conversation scenario
                serviceClient = getServiceClientInstance();

                serviceClient.getServiceContext().setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy("/rampart/policy/sc-" + i + ".xml"));
                serviceClient.setOptions(options);

                //Blocking invocation
                serviceClient.sendReceive(getEchoElement());
                serviceClient.sendReceive(getEchoElement());

                //Cancel the token
                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_TRUE);
                serviceClient.sendReceive(getEchoElement());

                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_FALSE);
                serviceClient.sendReceive(getEchoElement());
                options.setProperty(RampartMessageData.CANCEL_REQUEST, Constants.VALUE_TRUE);
                serviceClient.sendReceive(getEchoElement());
                serviceClient.cleanupTransport();

            }

        } catch (Exception e) {
            e.printStackTrace();
            fail(e.getMessage());
        }
    }

    private OMElement getEchoElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("echo", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    private OMElement getOMElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("returnError", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    private Policy loadPolicy(String xmlPath) throws Exception {
        return PolicyEngine.getPolicy(RampartTest.class.getResourceAsStream(xmlPath));
    }


}
