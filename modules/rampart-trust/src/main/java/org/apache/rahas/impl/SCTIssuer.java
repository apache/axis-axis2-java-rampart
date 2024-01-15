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

package org.apache.rahas.impl;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.util.UIDGenerator;
import org.apache.axis2.description.Parameter;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenIssuer;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.text.DateFormat;
import java.util.Date;
import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

public class SCTIssuer implements TokenIssuer {

    public final static String COMPUTED_KEY = "ComputedKey";

    private String configFile;

    private OMElement configElement;

    private String configParamName;

    /**
     * Issue a {@link SecurityContextToken} based on the wsse:Signature or
     * wsse:UsernameToken
     * <p>
     * This will support returning the SecurityContextToken with the following
     * types of wst:RequestedProof tokens:
     * <ul>
     * <li>xenc:EncryptedKey</li>
     * <li>wst:ComputedKey</li>
     * <li>wst:BinarySecret (for secure transport)</li>
     * </ul>
     */
    public SOAPEnvelope issue(RahasData data) throws TrustException {

        SCTIssuerConfig config = null;
        if (this.configElement != null) {
            config = SCTIssuerConfig
                    .load(configElement
                            .getFirstChildWithName(SCTIssuerConfig.SCT_ISSUER_CONFIG));
        }

        // Look for the file
        if (config == null && this.configFile != null) {
            config = SCTIssuerConfig.load(this.configFile);
        }

        // Look for the param
        if (config == null && this.configParamName != null) {
            Parameter param = data.getInMessageContext().getParameter(this.configParamName);
            if (param != null && param.getParameterElement() != null) {
                config = SCTIssuerConfig.load(param.getParameterElement()
                        .getFirstChildWithName(
                        SCTIssuerConfig.SCT_ISSUER_CONFIG));
            } else {
                throw new TrustException("expectedParameterMissing",
                                         new String[]{this.configParamName});
            }
        }

        if (config == null) {
            throw new TrustException("missingConfiguration",
                                     new String[]{SCTIssuerConfig.SCT_ISSUER_CONFIG
                                             .getLocalPart()});
        }

        // Env
        return createEnvelope(data, config);
    }

    private SOAPEnvelope createEnvelope(RahasData data,
                                        SCTIssuerConfig config) throws TrustException {
        try {
            SOAPEnvelope env = TrustUtil.createSOAPEnvelope(data.getSoapNs());
            int wstVersion = data.getVersion();

            // Get the document
            Document doc = ((Element) env).getOwnerDocument();

            SecurityContextToken sct =
                    new SecurityContextToken(this.getWSCVersion(data.getTokenType()), doc);
            
            // It appears WSS4J no longer includes an Id for SecurityContextToken automatically
            sct.setID(UIDGenerator.generateUID());

            OMElement rstrElem;
            if (wstVersion == RahasConstants.VERSION_05_12) {
                /**
                 * If secure conversation version is http://docs.oasis-open.org/ws-sx/ws-trust/200512
                 * We have to wrap "request security token response" in a "request security token response
                 * collection".
                 * See WS-SecureConversation 1.3 spec's Section 3 - Establishing Security Contexts
                 * for more details.
                 */
                OMElement requestedSecurityTokenResponseCollection = TrustUtil
                        .createRequestSecurityTokenResponseCollectionElement(wstVersion, env.getBody());
                rstrElem =
                        TrustUtil.createRequestSecurityTokenResponseElement(wstVersion,
                                requestedSecurityTokenResponseCollection);
            } else {
                rstrElem =
                        TrustUtil.createRequestSecurityTokenResponseElement(wstVersion,
                                env.getBody());
            }


            OMElement rstElem =
                    TrustUtil.createRequestedSecurityTokenElement(wstVersion, rstrElem);

            rstElem.addChild((OMElement) sct.getElement());

            String tokenType = data.getTokenType();

            OMElement reqAttachedRef = null;
            OMElement reqUnattachedRef = null;
            if (config.isAddRequestedAttachedRef()) {
                reqAttachedRef = TrustUtil.createRequestedAttachedRef(wstVersion,
                                                         rstrElem,
                                                         "#" + sct.getID(),
                                                         tokenType);
            }

            if (config.isAddRequestedUnattachedRef()) {
                reqUnattachedRef = TrustUtil.createRequestedUnattachedRef(wstVersion,
                                                           rstrElem,
                                                           sct.getIdentifier(),
                                                           tokenType);
            }

            //Creation and expiration times
            ZonedDateTime creationTime = ZonedDateTime.now(ZoneOffset.UTC);
            ZonedDateTime expirationTime = ZonedDateTime.ofInstant(Instant.ofEpochMilli(creationTime.toInstant().toEpochMilli() + config.getTtl()), ZoneOffset.UTC);

            // Add the Lifetime element
            TrustUtil.createLifetimeElement(wstVersion, rstrElem, DateUtil.getDateTimeFormatter(true).format(creationTime), DateUtil.getDateTimeFormatter(true).format(expirationTime));

            // Store the tokens
            Token sctToken = new Token(sct.getIdentifier(),
                                       (OMElement) sct.getElement(),
                                       Date.from(creationTime.toInstant()),
                                       Date.from(expirationTime.toInstant()));
            
            if(config.isAddRequestedAttachedRef()) {
                sctToken.setAttachedReference(reqAttachedRef.getFirstElement());
            }
            
            if(config.isAddRequestedUnattachedRef()) {
                sctToken.setUnattachedReference(reqUnattachedRef.getFirstElement());
            }

            byte[] secret = TokenIssuerUtil.getSharedSecret(data, config.getKeyComputation(), config.getKeySize());
            sctToken.setSecret(secret);
            
            //Add the RequestedProofToken
            TokenIssuerUtil.handleRequestedProofToken(data,
                                                      wstVersion,
                                                      config,
                                                      rstrElem,
                                                      sctToken,
                                                      doc);
            
            sctToken.setState(Token.ISSUED);
            TrustUtil.getTokenStore(data.getInMessageContext()).add(sctToken);
            return env;
        } catch (Exception e) {
            throw new TrustException(e.getMessage(), e);
        }
    }

    public String getResponseAction(RahasData data) throws TrustException {
        return TrustUtil.getActionValue(data.getVersion(), RahasConstants.RSTR_ACTION_SCT);
    }

    /**
     * @see org.apache.rahas.TokenIssuer#setConfigurationFile(java.lang.String)
     */
    public void setConfigurationFile(String configFile) {
        this.configFile = configFile;
    }

    /**
     * @see org.apache.rahas.TokenIssuer#setConfigurationElement(OMElement)
     */
    public void setConfigurationElement(OMElement configElement) {
        this.configElement = configElement;
    }

    public void setConfigurationParamName(String configParamName) {
        this.configParamName = configParamName;
    }

    private int getWSCVersion(String tokenTypeValue) throws WSSecurityException {

        if (tokenTypeValue == null) {
            return ConversationConstants.DEFAULT_VERSION;
        }

        if (tokenTypeValue.startsWith(ConversationConstants.WSC_NS_05_02)) {
            return ConversationConstants.getWSTVersion(ConversationConstants.WSC_NS_05_02);
        } else if (tokenTypeValue.startsWith(ConversationConstants.WSC_NS_05_12)) {
            return ConversationConstants.getWSTVersion(ConversationConstants.WSC_NS_05_12);
        } else {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "unsupportedSecConvVersion");
        }
    }
}
