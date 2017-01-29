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
import org.apache.axis2.context.MessageContext;
import org.apache.rahas.RahasData;
import org.apache.rahas.test.util.TestUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.joda.time.DateTime;
import org.w3c.dom.Document;

import java.io.File;

/**
 * Test class for SAML2 token issuer.
 */
public class SAML2TokenIssuerTest extends TestCase {

    public void testIssueToken() {
        // TODO
        Assert.assertTrue(true);
    }

    public void testCreateSubjectWithHolderOfKeySC() throws Exception {

        // TODO Its hard to do unit testing on TokenIssuer
        // Cos we need to construct complete message contexts with all
        // relevant data. This is more like an integration test rather than a
        // unit test. Therefore we need to refactor code to smaller testable units (methods)
        // and then only write tests.

        /*SAML2TokenIssuer saml2TokenIssuer = new SAML2TokenIssuer();

        MessageContext messageContext = new MessageContext();

        File file = new File("./sts-aar-resources/saml-issuer-config.xml");
        Assert.assertTrue(file.exists());

        SAMLTokenIssuerConfig samlTokenIssuerConfig = new SAMLTokenIssuerConfig(file.getAbsolutePath());
        Crypto crypto = TestUtil.getCrypto();
        DateTime creationDate = new DateTime();
        DateTime expirationDate = new DateTime(2050, 1, 1, 0, 0, 0, 0);
        RahasData rahasData = new RahasData(messageContext);*/

        /*Document document;
        Crypto crypto;
        DateTime creationDate;
        DateTime expirationDate;
        RahasData rahasData;*/





        //saml2TokenIssuer.createSubjectWithHolderOfKeySC()
    }
}
