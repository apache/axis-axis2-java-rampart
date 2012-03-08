/*
 * Copyright The Apache Software Foundation.
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

package org.apache.rahas.impl;

import junit.framework.Assert;
import junit.framework.TestCase;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.util.AXIOMUtil;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.client.STSClient;
import org.apache.rahas.test.util.AbstractTestCase;
import org.apache.rahas.test.util.TestSTSClient;
import org.apache.rahas.test.util.TestUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.joda.time.DateTime;
import org.opensaml.common.xml.SAMLConstants;
import org.w3c.dom.Document;

import java.io.File;

/**
 * Test class for SAML2 token issuer.
 */
public class SAML2TokenIssuerTest extends AbstractTestCase {

    private String configurationElement = "<configuration><saml-issuer-config>" +
            "<issuerName>Test_STS</issuerName>" +
            "<issuerKeyAlias>apache</issuerKeyAlias>" +
            "<issuerKeyPassword>password</issuerKeyPassword>" +
            "<cryptoProperties><crypto provider=\"org.apache.ws.security.components.crypto.Merlin\">" +
            "<property name=\"org.apache.ws.security.crypto.merlin.keystore.type\">JKS</property>" +
            "<property name=\"org.apache.ws.security.crypto.merlin.file\">src/test/resources/keystore.jks</property>" +
            "<property name=\"org.apache.ws.security.crypto.merlin.keystore.password\">password</property></crypto>" +
            "</cryptoProperties>" +
            "<timeToLive>300000</timeToLive>" +
            "<keySize>256</keySize>" +
            "<addRequestedAttachedRef /><addRequestedUnattachedRef />" +
            "<keyComputation>2</keyComputation>" +
            "<proofKeyType>BinarySecret</proofKeyType>" +
            "<trusted-services>" +
            "<service alias=\"apache\">http://10.100.3.196:9768/services/echo/</service>" +
            "</trusted-services></saml-issuer-config></configuration>";

    public void testCreateSubjectWithHolderOfKeySubjectConfirmation() throws Exception {

        RahasData rahasData = TestUtil.createTestRahasData("http://10.100.3.196:9768/services/echo/");

        SAML2TokenIssuer tokenIssuer = new SAML2TokenIssuer();
        tokenIssuer.setConfigurationElement(AXIOMUtil.stringToOM(this.configurationElement));
        SOAPEnvelope envelope = tokenIssuer.issue(rahasData);
        //System.out.println(envelope.toString());

        TestSTSClient stsClient = TestUtil.createTestSTSClient(SAMLConstants.SAML20_NS);

        Token token = stsClient.processResponse(RahasConstants.VERSION_05_02,
                envelope.getBody().getFirstElement(), "http://10.100.3.196:9768/services/echo/");

        Assert.assertNotNull(token.getToken());
    }

    public void testCreateSubjectWithBearerSubjectConfirmation() {
        // TODO
    }

    public void testCreateSubjectWithHOKSubjectConfirmationPublicCert() {
        // TODO
    }


}
