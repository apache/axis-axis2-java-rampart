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
package org.apache.rahas.test.util;

import junit.framework.Assert;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.CommonUtil;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.Properties;

/**
 * Utility class for tests.
 */
public class TestUtil {

    private static final Log log = LogFactory.getLog(TestUtil.class);

    public static Crypto getCrypto() throws IOException, WSSecurityException, TrustException {

        File file = new File("src/test/resources/crypto.config");
        Assert.assertTrue(file.exists());

        Properties properties = new Properties();
        try {
            properties.load(new FileInputStream(file));
        } catch (IOException e) {
            log.error("Unable to open crypto configuration file");
            throw e;
        }

        Crypto crypto = CryptoFactory.getInstance(properties);

        X509Certificate[] certificates = CommonUtil.getCertificatesByAlias(crypto, "apache");
        Assert.assertEquals(certificates.length, 1);

        return crypto;

    }
}
