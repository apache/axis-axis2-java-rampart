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

package org.apache.rampart.handler;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.validate.SignatureTrustValidator;

import java.security.cert.X509Certificate;

/**
 * Validates the certificate in a signature.
 */
public class CertificateValidator extends SignatureTrustValidator {

    private static Log log = LogFactory.getLog(CertificateValidator.class);

    CertificateValidator() {

    }

    /**
     * Checks the validity of the given certificate. For more info see SignatureTrustValidator.verifyTrustInCert.
     * @param certificate Certificate to be validated.
     * @param signatureCrypto Signature crypto instance.
     * @param requestData Set optional WSS4J values and pass this Object in
     * @return true if certificate used in signature is valid. False if it is not valid.
     * @throws WSSecurityException If an error occurred while trying to access Crypto and Certificate properties.
     */
    boolean validateCertificate(X509Certificate certificate, Crypto signatureCrypto, RequestData requestData) throws WSSecurityException {
        X509Certificate[] x509certs = new X509Certificate[1];
        x509certs[0] = certificate;
        try {
            verifyTrustInCerts(x509certs, signatureCrypto, requestData, false);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
	    return false;
        }
	return true;
    }

    /**
     * Checks the validity of the given certificate. For more info see SignatureTrustValidator.verifyTrustInCert. This method has been deprecated - use the method that passes in org.apache.wss4j.dom.handler.RequestData 
     * @param certificate Certificate to be validated.
     * @param signatureCrypto Signature crypto instance.
     * @return true if certificate used in signature is valid. False if it is not valid.
     * @throws WSSecurityException If an error occurred while trying to access Crypto and Certificate properties.
     */
    @Deprecated
    boolean validateCertificate(X509Certificate certificate, Crypto signatureCrypto) throws WSSecurityException {
        X509Certificate[] x509certs = new X509Certificate[1];
        x509certs[0] = certificate;
        RequestData requestData = new RequestData();
        try {
            verifyTrustInCerts(x509certs, signatureCrypto, requestData, false);
        } catch (Exception ex) {
            log.error(ex.getMessage(), ex);
	    return false;
        }
	return true;
    }
}
