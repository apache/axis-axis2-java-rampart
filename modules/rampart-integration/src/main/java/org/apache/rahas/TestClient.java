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

package org.apache.rahas;

import static org.apache.axis2.integration.TestConstants.TESTING_PATH;

import java.io.FileInputStream;
import java.io.InputStream;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.testutils.ClientHelper;
import org.apache.axis2.testutils.JettyServer;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rampart.RampartMessageData;
import org.junit.Rule;
import org.junit.Test;

public abstract class TestClient {

    @Rule
    public final JettyServer server = new JettyServer(TESTING_PATH + getServiceRepo(), false);

    @Rule
    public final ClientHelper clientHelper = new ClientHelper(server, TESTING_PATH + "rahas_client_repo");

    /**
     */
    @Test
    public void testRequest() throws Exception {
        ServiceClient serviceClient = clientHelper.createServiceClient("SecureService");
        Options options = serviceClient.getOptions();

        options.setTransportInProtocol(Constants.TRANSPORT_HTTP);
        options.setAction(this.getRequestAction());
//        options.setProperty(AddressingConstants.WS_ADDRESSING_VERSION, this.getWSANamespace());

        options.setTimeOutInMilliSeconds(200 * 1000);

        ServiceContext context = serviceClient.getServiceContext();
        context.setProperty(RampartMessageData.KEY_RAMPART_POLICY, loadPolicy());
        
        serviceClient.engageModule("addressing");
        serviceClient.engageModule("rampart");

        //Blocking invocation

        OMElement result = serviceClient.sendReceive(getRequest());

        this.validateRsponse(result);
    }

    protected String getWSANamespace() {
        return AddressingConstants.Submission.WSA_NAMESPACE;
    }

    public abstract OMElement getRequest();

    public abstract String getClientPolicyPath();

    public abstract String getServiceRepo();

    public abstract String getRequestAction() throws TrustException;

    public abstract void validateRsponse(OMElement resp);

//
//    /**
//     * This test will use WS-SecPolicy
//     */
//    public void testWithStsClient() {
//
//        // Get the repository location from the args
//        String repo = Constants.TESTING_PATH + "rahas_client_repo";
//
//        try {
//            ConfigurationContext configContext = ConfigurationContextFactory.createConfigurationContextFromFileSystem(repo,
//                                                                                                                      null);
//
//            STSClient client = new STSClient(configContext);
//
//            client.setAction(this.getRequestAction());
//
//            client.setRstTemplate(this.getRSTTemplate());
//            client.setVersion(this.getTrstVersion());
//
//            Token tok =
//                    client.requestSecurityToken(this.getServicePolicy(),
//                                                "http://127.0.0.1:" + port + "/axis2/services/SecureService",
//                                                this.getSTSPolicy(),
//                                                "http://localhost:5555/axis2/services/SecureService");
//
//            assertNotNull("Response token missing", tok);
//
//        } catch (Exception e) {
//            e.printStackTrace();
//            fail(e.getMessage());
//        }
//
//    }

    public abstract int getTrstVersion();

    public abstract Policy getServicePolicy() throws Exception;

    public abstract Policy getSTSPolicy() throws Exception;

    public abstract OMElement getRSTTemplate() throws TrustException;

    protected Policy getPolicy(String filePath) throws Exception {
        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(filePath));
        OMElement elem = builder.getDocumentElement();
        return PolicyEngine.getPolicy(elem);
    }
    
    private Policy loadPolicy() throws Exception {
    	String path = getClientPolicyPath();
    	InputStream poilicyStream = TestClient.class.getResourceAsStream(path);
		return PolicyEngine.getPolicy(poilicyStream);
    }


}
