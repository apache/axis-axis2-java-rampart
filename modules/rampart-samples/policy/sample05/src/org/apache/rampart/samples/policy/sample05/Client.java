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

package org.apache.rampart.samples.policy.sample05;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.om.OMXMLParserWrapper;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.client.STSClient;
import org.apache.rampart.RampartMessageData;
import org.apache.ws.secpolicy.SP11Constants;
import org.opensaml.saml.common.xml.SAMLConstants;

import java.io.FileInputStream;
import java.net.URL;

import javax.xml.namespace.QName;

/*
  sample 05 uses SAML token processing, unlike others such as sample 01 that uses username token processing

  1. Unit Tests that use Sample05, use in-memory objects, minimal XML marshalling → only Builder required
  2. Sample05: Full end-to-end SAML token creation with XML marshalling → Both builder AND marshaller required

  Sample05 calls this path:
  1. Client requests SAML token from STS
  2. → SAMLTokenIssuer.createAttributeAssertion()
  3. → CommonUtil.getSymmetricKeyBasedKeyInfo()
  4. → SAMLUtils.createEncryptedKey()
  5. → CommonUtil.buildXMLObject(SecurityTokenReference.ELEMENT_NAME)
  6. → OpenSAML tries to marshall the SecurityTokenReference to actual XML

  In the unit test, when KeyInfo is marshalled, OpenSAML handles the EncryptedKey as a
  child element and doesn't require the SecurityTokenReference to be independently
  marshallable. However, in sample05's STS token issuance process, the
  SecurityTokenReference objects need to be marshalled as standalone elements in the XML security header.

*/
public class Client {

	public static void main(String[] args) throws Exception {

		if(args.length != 3) {
			System.out.println("Usage: $java Client endpoint_address client_repo_path policy_xml_path");
		}

		ConfigurationContext ctx = ConfigurationContextFactory.createConfigurationContextFromFileSystem(args[1], null);

		STSClient stsClient = new STSClient(ctx);

		stsClient.setRstTemplate(getRSTTemplate());
		String action = TrustUtil.getActionValue(RahasConstants.VERSION_05_02, RahasConstants.RST_ACTION_ISSUE);
		stsClient.setAction(action);

		// Use the policy file path passed as argument
		String policyPath = args[2];
		String stsPolicyPath = policyPath.replace("policy.xml", "sts_policy.xml");

		String stsUrl = new URL(new URL(args[0]), "/axis2/services/STS").toString();

		Token responseToken = stsClient.requestSecurityToken(loadPolicy(policyPath), stsUrl, loadPolicy(stsPolicyPath), null);

	        System.out.println("\n############################# Requested Token ###################################\n");
	        System.out.println(responseToken.getToken().toString());
	        System.out.println("Token successfully received! Token ID: " + responseToken.getId());

	        TokenStorage store = TrustUtil.getTokenStore(ctx);
	        store.add(responseToken);

	        ServiceClient client = new ServiceClient(ctx, null);

	        Options options = new Options();
	        options.setAction("urn:echo");
	        options.setTo(new EndpointReference(args[0]));
	        // Force SOAP 1.2 to match STS call
	        options.setSoapVersionURI(org.apache.axiom.soap.SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI);

	        Policy servicePolicy = loadPolicy(policyPath);
	        options.setProperty(RampartMessageData.KEY_RAMPART_POLICY, servicePolicy);
	        options.setProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN, responseToken.getId());

	        client.setOptions(options);

	        client.engageModule("addressing");
                client.engageModule("rampart");

                OMElement response = client.sendReceive(getPayload("Hello world1"));
                System.out.println("Response  : " + response);
	        

	}

	private static Policy loadPolicy(String xmlPath) throws Exception {
		java.io.File policyFile = new java.io.File(xmlPath);

		if (!policyFile.exists()) {
			throw new Exception("Policy file not found: " + xmlPath);
		}

        OMXMLParserWrapper builder = OMXMLBuilderFactory.createOMBuilder(new FileInputStream(xmlPath));
        Policy policy = PolicyEngine.getPolicy(builder.getDocumentElement());
		return policy;
	}
	
    private static OMElement getSAMLToken(OMElement resp) {
        OMElement rst = resp.getFirstChildWithName(new QName(RahasConstants.WST_NS_05_02,
                                                             RahasConstants.IssuanceBindingLocalNames.
                                                                     REQUESTED_SECURITY_TOKEN));
        OMElement elem = rst.getFirstChildWithName(new QName( SAMLConstants.SAML20_NS , "Assertion"));
        return elem;
    }

	
    private static OMElement getPayload(String value) {
	OMFactory factory = OMAbstractFactory.getOMFactory();
	OMNamespace ns = factory.createOMNamespace("http://sample05.policy.samples.rampart.apache.org","ns1");
	OMElement elem = factory.createOMElement("echo", ns);
	OMElement childElem = factory.createOMElement("param0", null);
	childElem.setText(value);
	elem.addChild(childElem);
	        
	return elem;
	
    }
	
    private static OMElement getRSTTemplate() throws Exception {
	OMFactory fac = OMAbstractFactory.getOMFactory();
	OMElement elem = fac.createOMElement(SP11Constants.REQUEST_SECURITY_TOKEN_TEMPLATE);
	TrustUtil.createTokenTypeElement(RahasConstants.VERSION_05_02, elem).setText(RahasConstants.TOK_TYPE_SAML_10);
	TrustUtil.createKeyTypeElement(RahasConstants.VERSION_05_02, elem, RahasConstants.KEY_TYPE_SYMM_KEY);
	TrustUtil.createKeySizeElement(RahasConstants.VERSION_05_02, elem, 256);
	return elem;
    }  

}
