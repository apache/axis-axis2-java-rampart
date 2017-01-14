/*
 * Copyright 2004 - 2014 The Apache Software Foundation.
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

import java.net.URL;
import java.util.MissingResourceException;
import java.util.ResourceBundle;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.integration.JettyServer;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.junit.Rule;

/**
 * Base test class for integration tests that require Axis2 web application running in a web container.
 * The class uses Axis2 web application deployed via {@link JettyServer}.
 */
public abstract class AbstractRampartTest {
    
    /**
     * Default client connection timeout in milliseconds: {@value}
     */
    public static final int DEFAULT_CLIENT_CONNECTION_TIMEOUT_MILLIS = 200000;
    
    protected static final String RAMPART_CLIENT_REPO_PATH = "target/test-resources/rampart_client_repo";
    
    protected static final String RAMPART_SERVICE_REPO_PATH = "target/test-resources/rampart_service_repo";
    
    protected static ResourceBundle resources;
    
    @Rule
    public final JettyServer server = new JettyServer(
            RAMPART_SERVICE_REPO_PATH, isEnableHttp() ? 0 : -1, isEnableHttps() ? 0 : -1);
    
    static {
        try {
            resources = ResourceBundle.getBundle("org.apache.rampart.errors");
        } catch (MissingResourceException e) {
            throw new RuntimeException(e.getMessage());
        }
    }

    protected ServiceClient getServiceClientInstance() throws AxisFault {
        return getServiceClientInstance(null);
    }
    
    /**
     * Creates an Axis2 service client using the specified <code>wsdlUrl</code> and {@link #DEFAULT_CLIENT_CONNECTION_TIMEOUT_MILLIS}.
     * The service client will use Axis2 repository at {@link #RAMPART_CLIENT_REPO_PATH}.
     * @param wsdlUrl The wsdl url to initialize the service client with. Can be null in which case the client must be configured additionally (with policy, action etc.).
     * @return
     * @throws AxisFault
     */
    protected ServiceClient getServiceClientInstance(URL wsdlUrl) throws AxisFault {
        return getServiceClientInstance(wsdlUrl, DEFAULT_CLIENT_CONNECTION_TIMEOUT_MILLIS);
    }
    
    /**
     * Creates an Axis2 service client using the specified <code>wsdlUrl</code> and specified <code>connectionTimeoutMillis</code>.
     * The service client will use Axis2 repository at {@link #RAMPART_CLIENT_REPO_PATH}.
     * @param wsdlUrl The wsdl url to initialize the service client with. Can be null in which case the client must be configured additionally (with policy, action etc.).
     * @return
     * @throws AxisFault
     */
    protected ServiceClient getServiceClientInstance(URL wsdlUrl, int connectionTimeoutMillis) throws AxisFault {

        ConfigurationContext configContext = ConfigurationContextFactory.
                createConfigurationContextFromFileSystem(RAMPART_CLIENT_REPO_PATH, null);
        
        ServiceClient serviceClient;
        if (wsdlUrl == null) {
            serviceClient = new ServiceClient(configContext, null);
        }
        else {
            serviceClient = new ServiceClient(configContext, wsdlUrl, null, null);
        }
        
        serviceClient.getOptions().setTimeOutInMilliSeconds(connectionTimeoutMillis);
        serviceClient.getOptions().setProperty(HTTPConstants.SO_TIMEOUT, connectionTimeoutMillis);
        serviceClient.getOptions().setProperty(HTTPConstants.CONNECTION_TIMEOUT, connectionTimeoutMillis);

        serviceClient.engageModule("addressing");
        serviceClient.engageModule("rampart");

        return serviceClient;

    }
    
    protected OMElement getEchoElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("echo", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    protected OMElement getOMElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("returnError", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    protected Policy loadPolicy(String xmlPath) {
        return PolicyEngine.getPolicy(this.getClass().getResourceAsStream(xmlPath));
    }
    
    /**
     * @return Implementations must return <code>true</code> to enable startup of web container's http connector or false otherwise.
     */
    protected abstract boolean isEnableHttp();
    
    /**
     * @return Implementations must return <code>true</code> to enable startup of web container's https connector or false otherwise.
     */
    protected abstract boolean isEnableHttps();
}
