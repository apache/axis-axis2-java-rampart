/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *       http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package org.apache.rahas.impl;

import java.security.SecureRandom;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.CommonUtil;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.derivedKey.P_SHA1;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.KeyUtils;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.apache.wss4j.dom.message.WSSecEncryptedKey;
import org.apache.wss4j.dom.WSConstants;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

/**
 * 
 */
public class TokenIssuerUtil {

    public final static String ENCRYPTED_KEY = "EncryptedKey";
    public final static String BINARY_SECRET = "BinarySecret";

    public static byte[] getSharedSecret(RahasData data,
                                         int keyComputation,
                                         int keySize) throws TrustException {

        boolean reqEntrPresent = data.getRequestEntropy() != null;

        try {
            if (reqEntrPresent &&
                keyComputation != SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_USE_OWN_KEY) {
                //If there is requester entropy and if the issuer is not
                //configured to use its own key

                if (keyComputation ==
                    SAMLTokenIssuerConfig.KeyComputation.KEY_COMP_PROVIDE_ENT) {
                    data.setResponseEntropy(UsernameTokenUtil.generateNonce(keySize / 8));
                    P_SHA1 p_sha1 = new P_SHA1();
                    return p_sha1.createKey(data.getRequestEntropy(),
                                            data.getResponseEntropy(),
                                            0,
                                            keySize / 8);
                } else {
                    //If we reach this its expected to use the requestor's
                    //entropy
                    return data.getRequestEntropy();
                }
            } else { // need to use a generated key
                return generateEphemeralKey(keySize);
            }
        } catch (WSSecurityException e) {
            throw new TrustException("errorCreatingSymmKey", e);
        }
    }

    public static void handleRequestedProofToken(RahasData data,
                                                 int wstVersion,
                                                 AbstractIssuerConfig config,
                                                 OMElement rstrElem,
                                                 Token token,
                                                 Document doc) throws TrustException {
        OMElement reqProofTokElem =
                TrustUtil.createRequestedProofTokenElement(wstVersion, rstrElem);

        if (config.keyComputation == AbstractIssuerConfig.KeyComputation.KEY_COMP_PROVIDE_ENT
            && data.getRequestEntropy() != null) {
            //If we there's requester entropy and its configured to provide
            //entropy then we have to set the entropy value and
            //set the RPT to include a ComputedKey element

            OMElement respEntrElem = TrustUtil.createEntropyElement(wstVersion, rstrElem);
            String entr = Base64Utils.encode(data.getResponseEntropy());
            OMElement binSecElem = TrustUtil.createBinarySecretElement(wstVersion,
                                                            respEntrElem,
                                                            RahasConstants.BIN_SEC_TYPE_NONCE);
            binSecElem.setText(entr);

            OMElement compKeyElem =
                    TrustUtil.createComputedKeyElement(wstVersion, reqProofTokElem);
            compKeyElem.setText(data.getWstNs() + RahasConstants.COMPUTED_KEY_PSHA1);
        } else {
            if (TokenIssuerUtil.ENCRYPTED_KEY.equals(config.proofKeyType)) {

                WSSecEncryptedKey encrKeyBuilder = new WSSecEncryptedKey(doc);
                Crypto crypto;

                ClassLoader classLoader = data.getInMessageContext().getAxisService().getClassLoader();

                if (config.cryptoElement != null) { // crypto props defined as elements
                    crypto = CommonUtil.getCrypto(TrustUtil.toProperties(config.cryptoElement),classLoader);
                } else { // crypto props defined in a properties file
                    crypto = CommonUtil.getCrypto(config.cryptoPropertiesFile, classLoader);
                }
                
                SecretKey symmetricKey = null;
                try {
                    KeyGenerator keyGen = KeyUtils.getKeyGenerator(WSConstants.AES_128);
                    symmetricKey = keyGen.generateKey();
                    encrKeyBuilder.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);

                } catch (WSSecurityException e) {
                    throw new TrustException("errorCreatingSecretKey", e);
                }

                try {
                    encrKeyBuilder.setUseThisCert(data.getClientCert());
                    encrKeyBuilder.prepare(crypto, symmetricKey);
                } catch (WSSecurityException e) {
                    throw new TrustException("errorInBuildingTheEncryptedKeyForPrincipal",
                                             new String[]{data.
                                                     getClientCert().getSubjectDN().getName()});
                }
                Element encryptedKeyElem = encrKeyBuilder.getEncryptedKeyElement();
                Element bstElem = encrKeyBuilder.getBinarySecurityTokenElement();
                if (bstElem != null) {
                    reqProofTokElem.addChild((OMElement) bstElem);
                }

                reqProofTokElem.addChild((OMElement) encryptedKeyElem);

                token.setSecret(encrKeyBuilder.getEncryptedKeySHA1().getBytes());
            } else if (TokenIssuerUtil.BINARY_SECRET.equals(config.proofKeyType)) {
                byte[] secret = TokenIssuerUtil.getSharedSecret(data,
                                                                config.keyComputation,
                                                                config.keySize);
                OMElement binSecElem = TrustUtil.createBinarySecretElement(wstVersion,
                                                                           reqProofTokElem,
                                                                           null);
                binSecElem.setText(Base64Utils.encode(secret));
                token.setSecret(secret);
            } else {
                throw new IllegalArgumentException(config.proofKeyType);
            }
        }
    }

    private static byte[] generateEphemeralKey(int keySize) throws TrustException {
        try {
            SecureRandom random = SecureRandom.getInstance("SHA1PRNG");
            byte[] temp = new byte[keySize / 8];
            random.nextBytes(temp);
            return temp;
        } catch (Exception e) {
            throw new TrustException("errorCreatingSymmKey", e);
        }
    }

}
