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

package org.apache.rahas.client;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMException;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.om.OMXMLBuilderFactory;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.util.base64.Base64Utils;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.client.Options;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.description.AxisOperation;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.OutInAxisOperation;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.CommonUtil;
import org.apache.ws.secpolicy.model.AlgorithmSuite;
import org.apache.ws.secpolicy.model.Binding;
import org.apache.ws.secpolicy.model.Trust10;
import org.apache.ws.secpolicy.model.Trust13;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.derivedKey.P_SHA1;
import org.apache.wss4j.common.token.Reference;
import org.apache.wss4j.common.util.UsernameTokenUtil;
import org.w3c.dom.Element;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.security.auth.callback.UnsupportedCallbackException;
import javax.xml.namespace.QName;
import java.io.IOException;
import java.text.DateFormat;
import java.util.ArrayList;
import java.util.Date;
import java.util.Iterator;
import java.util.List;
import java.util.UUID;
import java.time.ZonedDateTime;

public class STSClient {

    private static final String RAMPART_POLICY = "rampartPolicy";

    private static Log log = LogFactory.getLog(STSClient.class);

    private String action;

    private OMElement rstTemplate;

    private int version = RahasConstants.VERSION_05_02;

    private Options options;

    private Trust10 trust10;
    
    private Trust13 trust13;

    private AlgorithmSuite algorithmSuite;
    
    private ArrayList parameters = new ArrayList();

    private byte[] requestorEntropy;

    private String addressingNs = AddressingConstants.Submission.WSA_NAMESPACE;

    private int keySize;
    
    private String soapVersion = SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI;

    /**
     * Life time in seconds
     * Default is 300 seconds (5 mins)
     */
    private int ttl = 300;
    private Crypto crypto;
    private CallbackHandler cbHandler;
    private ConfigurationContext configCtx;

    public STSClient(ConfigurationContext configCtx) throws TrustException {
        if (configCtx != null) {
            this.configCtx = configCtx;
        } else {
            throw new TrustException("stsClientCfgCtxNull");
        }
    }

    public Token requestSecurityToken(Policy servicePolicy,
                                      String issuerAddress,
                                      Policy issuerPolicy,
                                      String appliesTo) throws TrustException {
        try {
            QName rstQn = new QName("requestSecurityToken");

            ServiceClient client = getServiceClient(rstQn, issuerAddress);
            
            for (int i = 0; i < parameters.size(); i++) {
                Parameter param = (Parameter)parameters.get(i);
                client.getAxisService().addParameter(param.getName(), param.getValue());
            }
            
            client.getServiceContext().setProperty(RAMPART_POLICY, issuerPolicy);
            client.getOptions().setSoapVersionURI(this.soapVersion);

            if(this.addressingNs != null) {
                client.getOptions().setProperty(AddressingConstants.WS_ADDRESSING_VERSION, this.addressingNs);
            }
            client.engageModule("addressing");
            client.engageModule("rampart");

            //Process the STS and service policy policy
            this.processPolicy(issuerPolicy, servicePolicy);
            
            try {
                OMElement response = client.sendReceive(rstQn,
                                                        createIssueRequest(appliesTo));
    
                return processIssueResponse(version, response, issuerAddress);
            } finally {
                client.cleanupTransport();
            }
        } catch (AxisFault e) {
            log.error("errorInObtainingToken", e);
            throw new TrustException("errorInObtainingToken", new String[]{issuerAddress},e);
        }
    }

    /**
     * Cancel a particular security token
     *
     * @param issuerAddress
     * @param tokenId
     * @return true is the Token was successfully canceled. False otherwise.
     * @throws TrustException
     */
    public boolean cancelToken(String issuerAddress,
                               String tokenId,
                               String action) throws TrustException {
        try {
            QName rstQn = new QName("cancelSecurityToken");
            ServiceClient client = getServiceClient(rstQn, issuerAddress);
            if(action != null) {
                client.getOptions().setAction(action);
            }
            
            return processCancelResponse(client.sendReceive(rstQn,
                                                            createCancelRequest(tokenId)));
        } catch (AxisFault e) {
            log.error("errorInCancelingToken", e);
            throw new TrustException("errorInCancelingToken", e);
        }
    }
    
    public boolean validateToken(String tokenId,
                                 String issuerAddress,
                                 Policy issuerPolicy) throws TrustException {
        try {
            QName rstQn = new QName("requestSecurityToken");
            String requestType =
                    TrustUtil.getWSTNamespace(version) + RahasConstants.REQ_TYPE_VALIDATE;
            
            ServiceClient client = getServiceClient(rstQn, issuerAddress);
            
            client.getServiceContext().setProperty(RAMPART_POLICY, issuerPolicy);
            client.getOptions().setSoapVersionURI(this.soapVersion);
            if(this.addressingNs != null) {
                client.getOptions().setProperty(AddressingConstants.WS_ADDRESSING_VERSION, this.addressingNs);
            }
            client.engageModule("addressing");
            client.engageModule("rampart");

            this.processPolicy(issuerPolicy, null);
            
            OMElement response = client.sendReceive(rstQn,
                                                    createValidateRequest(requestType,tokenId));
            
            return true;
            
            
        } catch (AxisFault e) {
            log.error("errorInValidatingToken", e);
            throw new TrustException("errorInValidatingToken", new String[]{issuerAddress},e);
        }
        
    }
    
    public boolean renewToken(String tokenId,
                              String issuerAddress,
                              Policy issuerPolicy) throws TrustException {
        
        try {
        QName rstQn = new QName("requestSecurityToken");
        
        ServiceClient client = getServiceClient(rstQn, issuerAddress);
        
        client.getServiceContext().setProperty(RAMPART_POLICY, issuerPolicy);
        client.getOptions().setSoapVersionURI(this.soapVersion);
        if(this.addressingNs != null) {
            client.getOptions().setProperty(AddressingConstants.WS_ADDRESSING_VERSION, this.addressingNs);
        }
        client.engageModule("addressing");
        client.engageModule("rampart");

        this.processPolicy(issuerPolicy, null);
        
        String tokenType = RahasConstants.TOK_TYPE_SAML_10;
        
        OMElement response = client.sendReceive(rstQn,
                                                createRenewRequest(tokenType,tokenId));
        
        return true;
        
        } catch (AxisFault e) {
            log.error("errorInRenewingToken", e);
            throw new TrustException("errorInRenewingToken", new String[]{issuerAddress},e); 
        }
        
    }

    /**
     * Renews the token referenced by the token id, updates the token store
     * @param tokenId
     * @param issuerAddress
     * @param issuerPolicy
     * @param store
     * @return status
     * @throws TrustException
     */
    public boolean renewToken(String tokenId,
                              String issuerAddress,
                              Policy issuerPolicy, TokenStorage store) throws TrustException {

        try {
            QName rstQn = new QName("requestSecurityToken");

            ServiceClient client = getServiceClient(rstQn, issuerAddress);

            client.getServiceContext().setProperty(RAMPART_POLICY, issuerPolicy);
            client.getOptions().setSoapVersionURI(this.soapVersion);
            if (this.addressingNs != null) {
                client.getOptions().setProperty(AddressingConstants.WS_ADDRESSING_VERSION, this.addressingNs);
            }
            client.engageModule("addressing");
            client.engageModule("rampart");

            this.processPolicy(issuerPolicy, null);

            String tokenType = RahasConstants.TOK_TYPE_SAML_10;

            OMElement response = client.sendReceive(rstQn,
                    createRenewRequest(tokenType, tokenId));
            store.update(processRenewResponse(version, response, store, tokenId));

            return true;

        } catch (AxisFault e) {
            log.error("errorInRenewingToken", e);
            throw new TrustException("errorInRenewingToken", new String[]{issuerAddress}, e);
        }

    }

    /**
     * Processes the response and update the token store
     * @param version
     * @param elem
     * @param store
     * @param id
     * @return
     * @throws TrustException
     */
    private Token processRenewResponse(int version, OMElement elem, TokenStorage store, String id) throws TrustException {
        OMElement rstr = elem;
        if (version == RahasConstants.VERSION_05_12) {
            //The WS-SX result will be an RSTRC
            rstr = elem.getFirstElement();
        }
        //get the corresponding WS-Trust NS
        String ns = TrustUtil.getWSTNamespace(version);

        //Get the RequestedAttachedReference
        OMElement reqSecToken = rstr.getFirstChildWithName(new QName(
                ns, RahasConstants.IssuanceBindingLocalNames.REQUESTED_SECURITY_TOKEN));

        if (reqSecToken == null) {
            throw new TrustException("reqestedSecTokMissing");
        }

        //Extract the life-time element
        OMElement lifeTimeEle = rstr.getFirstChildWithName(new QName(
                ns, RahasConstants.IssuanceBindingLocalNames.LIFETIME));

        if (lifeTimeEle == null) {
            throw new TrustException("lifeTimeElemMissing");
        }

        //update the existing token
        OMElement tokenElem = reqSecToken.getFirstElement();
        Token token = store.getToken(id);
        token.setPreviousToken(token.getToken());
        token.setToken(tokenElem);
        token.setState(Token.RENEWED);
        token.setExpires(extractExpiryDate(lifeTimeEle));

        return token;
    }

    /**
     * extracts the expiry date from the Lifetime element of the RSTR
     * @param lifetimeElem
     * @return
     * @throws TrustException
     */
    private Date extractExpiryDate(OMElement lifetimeElem) throws TrustException {
        try {
            OMElement expiresElem =
                    lifetimeElem.getFirstChildWithName(new QName(WSConstants.WSU_NS,
                            WSConstants.EXPIRES_LN));
            ZonedDateTime expiresDateTime = ZonedDateTime.parse(expiresElem.getText());
            return java.util.Date.from(expiresDateTime.toInstant());
        } catch (OMException e) {
            throw new TrustException("lifeTimeProcessingError",
                    new String[]{lifetimeElem.toString()}, e);
        } catch (Exception e) {
            throw new TrustException("lifeTimeProcessingError",
                    new String[]{lifetimeElem.toString()}, e);
        }
    }


    private ServiceClient getServiceClient(QName rstQn,
                                           String issuerAddress) throws AxisFault {
        AxisService axisService =
                new AxisService("SecurityTokenService" + UUID.randomUUID().toString());
        axisService.setClientSide(true);
        AxisOperation operation = new OutInAxisOperation(rstQn);
        axisService.addOperation(operation);
        ServiceClient client = new ServiceClient(this.configCtx, axisService);

        if (this.options != null) {
            client.setOptions(options);
        }

        //Set the action
        client.getOptions().setAction(action);
        client.getOptions().setTo(new EndpointReference(issuerAddress));
        client.engageModule("rampart");
        return client;
    }

    /**
     * Processes the response from Token issuer.
     * @param version The supported version.
     * @param result Resulting token response from token issuer.
     * @param issuerAddress The respective token applying entity (as a url)
     * @return The issued token.
     * @throws TrustException If an error occurred while extracting token from response.
     */
    protected Token processIssueResponse(int version, OMElement result,
            String issuerAddress) throws TrustException {
        OMElement rstr = result;

        /**
         * TODO :-
         * There are 3 mechanisms to establish a security context token.
         * They are,
         * 1. Security context token created by a security token service
         * 2. Security context token created by one of the communicating parties and propagated with a
         * message
         * 3. Security context token created through negotiation/exchanges
         *
         * As per now we are only supporting case 1. Therefore we always expect a
         * wst:RequestSecurityTokenResponseCollection in the incoming message.
         *
         * This only applies when we use specification http://docs.oasis-open.org/ws-sx/ws-secureconversation/200512
         */

        if (version == RahasConstants.VERSION_05_12) {
            //The WS-SX result will be an RSTRC
            rstr = result.getFirstElement();
        }

        String ns = TrustUtil.getWSTNamespace(version);

        //Get the RequestedAttachedReference
        OMElement reqAttElem = rstr.getFirstChildWithName(new QName(
                ns, RahasConstants.IssuanceBindingLocalNames.REQUESTED_ATTACHED_REFERENCE));
        OMElement reqAttRef = reqAttElem == null ? null : reqAttElem.getFirstElement();

        //Get the RequestedUnattachedReference
        OMElement reqUnattElem =
                rstr.getFirstChildWithName(new QName(ns,
                                                     RahasConstants.IssuanceBindingLocalNames.
                                                             REQUESTED_UNATTACHED_REFERENCE));
        OMElement reqUnattRef = reqUnattElem == null ? null : reqUnattElem.getFirstElement();

        //Get the security token
        OMElement reqSecTok =
                rstr.getFirstChildWithName(new QName(ns,
                                                     RahasConstants.IssuanceBindingLocalNames.
                                                             REQUESTED_SECURITY_TOKEN));
        if (reqSecTok == null) {
            throw new TrustException("reqestedSecTokMissing");
        }

        OMElement tokenElem = reqSecTok.getFirstElement();

        String id = this.findIdentifier(reqAttRef, reqUnattRef, tokenElem);

        if (id == null) {
            throw new TrustException("cannotObtainTokenIdentifier");
        }

        OMElement lifeTimeEle =
                rstr.getFirstChildWithName(new QName(ns,
                                                     RahasConstants.IssuanceBindingLocalNames.
                                                             LIFETIME));

        Token token = new Token(id, tokenElem, lifeTimeEle);
        token.setIssuerAddress(issuerAddress);
        token.setAttachedReference(reqAttRef);
        token.setUnattachedReference(reqUnattRef);

        //Handle proof token
        OMElement rpt =
                rstr.getFirstChildWithName(new QName(ns,
                                                     RahasConstants.LocalNames.
                                                             REQUESTED_PROOF_TOKEN));

        byte[] secret = null;

        if (rpt != null) {
            OMElement child = rpt.getFirstElement();
            if (child == null) {
                throw new TrustException("invalidRPT");
            }
            if (child.getQName().equals(new QName(ns,
                                                  RahasConstants.LocalNames.
                                                          BINARY_SECRET))) {
                //First check for the binary secret
                String b64Secret = child.getText();
                secret = Base64Utils.decode(b64Secret);
            } else if (child.getQName().equals(new QName(ns, WSConstants.ENC_KEY_LN))) {

                Element domChild = (Element)OMXMLBuilderFactory.createStAXOMBuilder(
                        OMAbstractFactory.getMetaFactory(
                                OMAbstractFactory.FEATURE_DOM).getOMFactory(),
                        child.getXMLStreamReader()).getDocumentElement();

                try {
                    RequestData requestData = new RequestData();
	            boolean disableBSPEnforcement = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.DISABLE_BSP_ENFORCEMENT) != null) {
	                disableBSPEnforcement = Boolean.parseBoolean((String) this.options.getProperty(RahasConstants.DISABLE_BSP_ENFORCEMENT));
                        requestData.setDisableBSPEnforcement(disableBSPEnforcement);
		    }
	            boolean allowUsernameTokenNoPassword = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.ALLOW_USERNAME_TOKEN_NO_PASSWORD) != null) {
	                allowUsernameTokenNoPassword = Boolean.parseBoolean((String) this.options.getProperty(RahasConstants.ALLOW_USERNAME_TOKEN_NO_PASSWORD));
                        requestData.setAllowUsernameTokenNoPassword(allowUsernameTokenNoPassword);
		    }

                    int timeStampFutureTTL = 60;
                    if (this.options != null && this.options.getProperty(RahasConstants.TIMESTAMP_FUTURE_TTL) != null) {
	                timeStampFutureTTL = Integer.valueOf((String) this.options.getProperty(RahasConstants.TIMESTAMP_FUTURE_TTL));
                        requestData.setTimeStampFutureTTL(timeStampFutureTTL);
		    }

                    int utTTL = 300;
                    if (this.options != null && this.options.getProperty(RahasConstants.UT_TTL) != null) {
	                utTTL = Integer.valueOf((String) this.options.getProperty(RahasConstants.UT_TTL));
                        requestData.setUtTTL(utTTL);
		    }

                    int utFutureTTL = 60;
                    if (this.options != null && this.options.getProperty(RahasConstants.UT_FUTURE_TTL) != null) {
	                utFutureTTL = Integer.valueOf((String) this.options.getProperty(RahasConstants.UT_FUTURE_TTL));
                        requestData.setUtFutureTTL(utFutureTTL);
		    }

                    /* WSS4J sets this as false however before 1.8.0 this was hard-coded to true */
                    boolean handleCustomPasswordTypes = true;
                    if (this.options != null && this.options.getProperty(RahasConstants.HANDLE_CUSTOM_PASSWORD_TYPES) != null) {
	                handleCustomPasswordTypes = Boolean.valueOf((String) this.options.getProperty(RahasConstants.HANDLE_CUSTOM_PASSWORD_TYPES));
                        requestData.setHandleCustomPasswordTypes(handleCustomPasswordTypes);
		    }

                    boolean allowNamespaceQualifiedPasswordTypes = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.ALLOW_NAMESPACE_QUALIFIED_PASSWORDTYPES) != null) {
	                allowNamespaceQualifiedPasswordTypes = Boolean.valueOf((String) this.options.getProperty(RahasConstants.ALLOW_NAMESPACE_QUALIFIED_PASSWORDTYPES));
                        requestData.setAllowNamespaceQualifiedPasswordTypes(allowNamespaceQualifiedPasswordTypes);
		    }

                    boolean encodePasswords = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.ENCODE_PASSWORDS) != null) {
	                encodePasswords = Boolean.valueOf((String) this.options.getProperty(RahasConstants.ENCODE_PASSWORDS));
                        requestData.setEncodePasswords(encodePasswords);
		    }

                    boolean validateSamlSubjectConfirmation = false; // backward compatibility
                    if (this.options != null && this.options.getProperty(RahasConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION) != null) {
	                validateSamlSubjectConfirmation = Boolean.valueOf((String) this.options.getProperty(RahasConstants.VALIDATE_SAML_SUBJECT_CONFIRMATION));
                        requestData.setValidateSamlSubjectConfirmation(validateSamlSubjectConfirmation);
		    }

                    boolean allowRSA15KeyTransportAlgorithm = true; // backward compatibility
                    if (this.options != null && this.options.getProperty(RahasConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM) != null) {
	                allowRSA15KeyTransportAlgorithm = Boolean.valueOf((String) this.options.getProperty(RahasConstants.ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM));
                        requestData.setAllowRSA15KeyTransportAlgorithm(allowRSA15KeyTransportAlgorithm);
		    }

                    boolean timestampStrict = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.TIMESTAMP_STRICT_LN) != null) {
	                timestampStrict = Boolean.valueOf((String) this.options.getProperty(RahasConstants.TIMESTAMP_STRICT_LN));
                        requestData.setTimeStampStrict(timestampStrict);
		    }

                    boolean timestampPrecisionInMs = false;
                    if (this.options != null && this.options.getProperty(RahasConstants.TIMESTAMP_STRICT_LN) != null) {
	                timestampPrecisionInMs = Boolean.valueOf((String) this.options.getProperty(RahasConstants.TIMESTAMP_PRECISION_IN_MS_LN));
                        requestData.setPrecisionInMilliSeconds(timestampPrecisionInMs);
		    }

                    secret = CommonUtil.getDecryptedBytes(this.cbHandler, this.crypto, domChild, requestData);
                } catch (WSSecurityException e) {
                    log.error("Error decrypting encrypted key element", e);
                    throw new TrustException("errorInProcessingEncryptedKey", e);
                }

            } else if (child.getQName().equals(new QName(ns,
                    RahasConstants.IssuanceBindingLocalNames.
                            COMPUTED_KEY))) {
                //Handle the computed key

                //Get service entropy
                OMElement serviceEntrElem = rstr
                        .getFirstChildWithName(new QName(ns,
                                                         RahasConstants.IssuanceBindingLocalNames.
                                                                 ENTROPY));

                OMElement binSecElem = serviceEntrElem.getFirstElement();

                if (binSecElem != null && binSecElem.getText() != null
                    && !"".equals(binSecElem.getText().trim())) {

                    byte[] serviceEntr = Base64Utils.decode(binSecElem.getText());

                    //Right now we only use PSHA1 as the computed key algo                    
                    P_SHA1 p_sha1 = new P_SHA1();

                    int length = (this.keySize > 0) ? keySize
                                 : this.algorithmSuite
                            .getMaximumSymmetricKeyLength();
                    try {
                        secret = p_sha1.createKey(this.requestorEntropy, serviceEntr, 0, length/8);
                    } catch (WSSecurityException e) {
                        throw new TrustException("keyDerivationError", e);
                    }
                } else {
                    //Service entropy missing
                    throw new TrustException("serviceEntropyMissing");
                }
            }

        } else {
            if (this.requestorEntropy != null) {
                //Use requester entropy as the key
                secret = this.requestorEntropy;
            }
        }
        token.setSecret(secret);
        return token;
    }

    private boolean processCancelResponse(OMElement response) {
        /*
        <wst:RequestSecurityTokenResponse>
            <wst:RequestedTokenCancelled/>
        </wst:RequestSecurityTokenResponse>
        */
        return response.
                getFirstChildWithName(new QName(RahasConstants.
                        CancelBindingLocalNames.REQUESTED_TOKEN_CANCELED)) != null;
    }

    /**
     * Find the token identifier.
     *
     * @param reqAttRef
     * @param reqUnattRef
     * @param token
     * @return id
     */
    private String findIdentifier(OMElement reqAttRef,
                                  OMElement reqUnattRef,
                                  OMElement token) {
        String id;
        if (reqAttRef != null) {
            //First try the attached ref
            id = this.getIdFromSTR(reqAttRef);
        } else if (reqUnattRef != null) {
            //then try the unattached ref
            id = this.getIdFromSTR(reqUnattRef);
        } else {
            //Return wsu:Id of the token element
            id = token.getAttributeValue(new QName(WSConstants.WSU_NS, "Id"));
            if ( id == null )
            {
                // If we are dealing with a SAML Assetion, look for AssertionID.
                id = token.getAttributeValue(new QName( "AssertionID"));
            }
        }
        return id;
    }


    /**
     * Process the given STR to find the id it refers to
     *
     * @param refElem
     * @return id
     */
    private String getIdFromSTR(OMElement refElem) {
        //ASSUMPTION:SecurityTokenReference/KeyIdentifier
        OMElement child = refElem.getFirstElement();
        if(child == null) {
            return null;
        }
        
        if (child.getQName().equals(new QName(WSConstants.SIG_NS, "KeyInfo")) ||
                child.getQName().equals(new QName(WSConstants.WSSE_NS, "KeyIdentifier"))) {
            return child.getText();
        } else if(child.getQName().equals(Reference.TOKEN)) {
            return child.getAttributeValue(new QName("URI"));
        } else {
            return null;
        }

    }

    /**
     * Process the goven service policy and extract the info required to create
     * the RST.
     *
     * @param servicePolicy
     * @throws TrustException 
     */
    private void processPolicy(Policy issuerPolicy, Policy servicePolicy) throws TrustException {
        //Get the policy assertions
        //Assumption: there's only one alternative

        if (issuerPolicy != null) {
            log.debug("Processing Issuer policy");

            List issuerAssertions = (List) issuerPolicy.getAlternatives().next();

            for (Iterator iter = issuerAssertions.iterator(); iter.hasNext();) {
                Assertion tempAssertion = (Assertion) iter.next();
                //find the AlgorithmSuite assertion
                if (tempAssertion instanceof Binding) {

                    log.debug("Extracting algo suite from issuer policy binding");

                    this.algorithmSuite = ((Binding) tempAssertion)
                            .getAlgorithmSuite();
                    
                    if(algorithmSuite == null) {
                        throw new TrustException("Invalid STS policy. AlgorithmSuite not found");
                    }
                }
            }
        }

        if (servicePolicy != null) {

            log.debug("Processing service policy to find Trust10 assertion");

            List assertions = (List) servicePolicy.getAlternatives().next();

            for (Iterator iter = assertions.iterator(); iter.hasNext();) {
                Assertion tempAssertion = (Assertion) iter.next();
                //find the Trust10 assertion
                if (tempAssertion instanceof Trust10) {
                    log.debug("Extracting Trust10 assertion from service policy");
                    this.trust10 = (Trust10) tempAssertion;
                } else if (tempAssertion instanceof Trust13) {
                    log.debug("Extracting Trust13 assertion from service policy");
                    this.trust13 = (Trust13) tempAssertion;
                }
            }
        }
    }

    /**
     * This creates a request security token (RST) message.
     * @param appliesTo The address which token is applicable to.
     * @return The axiom object representation of RST.
     * @throws TrustException If an error occurred while creating the RST.
     */
    protected OMElement createIssueRequest(String appliesTo) throws TrustException {

        String requestType =
                    TrustUtil.getWSTNamespace(version) + RahasConstants.REQ_TYPE_ISSUE;

        if (log.isDebugEnabled()) {
            log.debug("Creating request with request type: " + requestType +
                      " and applies to: " + appliesTo);
        }

        OMElement rst = TrustUtil.createRequestSecurityTokenElement(version);

        TrustUtil.createRequestTypeElement(this.version, rst, requestType);
        if (appliesTo != null) {
            TrustUtil.createAppliesToElement(rst, appliesTo, this.addressingNs);
        }
        TrustUtil.createLifetimeElement(this.version, rst, this.ttl * 1000);

        //Copy over the elements from the template
        if (this.rstTemplate != null) {

            if (log.isDebugEnabled()) {
                log.debug("Using RSTTemplate: " + this.rstTemplate.toString());
            }

            Iterator templateChildren = rstTemplate.getChildElements();
            while (templateChildren.hasNext()) {
                OMElement child = (OMElement) templateChildren.next();
                rst.addChild(child.cloneOMElement());
                //Look for the key size element
                if (child.getQName().equals(
                        new QName(TrustUtil.getWSTNamespace(this.version),
                                  RahasConstants.IssuanceBindingLocalNames.KEY_SIZE))) {
                    log.debug("Extracting key size from the RSTTemplate: ");
                    this.keySize =
                            (child.getText() != null && !"".equals(child.getText())) ?
                            Integer.parseInt(child.getText()) :
                            -1;
                    if (log.isDebugEnabled()) {
                        log.debug("Key size from RSTTemplate: " + this.keySize);
                    }
                }
            }
        }
        
        int nonceLength = this.algorithmSuite != null ? this.algorithmSuite.getMaximumSymmetricKeyLength() / 8 : 16;

        try {
            // Handle entropy
            if (this.trust10 != null) {

                log.debug("Processing Trust assertion");

                if (this.trust10.isRequireClientEntropy()) {

                    log.debug("Requires client entropy");

                    // setup requestor entropy
                    OMElement ent = TrustUtil.createEntropyElement(this.version, rst);
                    OMElement binSec =
                            TrustUtil.createBinarySecretElement(this.version,
                                                                ent,
                                                                RahasConstants.BIN_SEC_TYPE_NONCE);
                    this.requestorEntropy =
                            UsernameTokenUtil.generateNonce(nonceLength);
                    binSec.setText(Base64Utils.encode(this.requestorEntropy));

                    if (log.isDebugEnabled()) {
                        log.debug("Clien entropy : " + Base64Utils.encode(this.requestorEntropy));
                    }

                    // Add the ComputedKey element
                    TrustUtil.createComputedKeyAlgorithm(this.version, rst,
                                                         RahasConstants.COMPUTED_KEY_PSHA1);
                }
                
            } else if (this.trust13 != null) {
                
                if (this.trust13.isRequireClientEntropy()) {

                    log.debug("Requires client entropy");

                    // setup requestor entropy
                    OMElement ent = TrustUtil.createEntropyElement(this.version, rst);
                    OMElement binSec =
                            TrustUtil.createBinarySecretElement(this.version,
                                                                ent,
                                                                RahasConstants.BIN_SEC_TYPE_NONCE);
                    this.requestorEntropy =
                            UsernameTokenUtil.generateNonce(nonceLength);
                    binSec.setText(Base64Utils.encode(this.requestorEntropy));

                    if (log.isDebugEnabled()) {
                        log.debug("Clien entropy : " + Base64Utils.encode(this.requestorEntropy));
                    }

                    // Add the ComputedKey element
                    TrustUtil.createComputedKeyAlgorithm(this.version, rst,
                                                         RahasConstants.COMPUTED_KEY_PSHA1);
                }
                
            }
            
            
            
            
        } catch (Exception e) {
            throw new TrustException("errorSettingUpRequestorEntropy", e);
        }

        
        return rst;
        
    }
    
    private OMElement createValidateRequest(String requestType, String tokenId) throws TrustException {

        if (log.isDebugEnabled()) {
            log.debug("Creating request with request type: " + requestType);
        }

        OMElement rst = TrustUtil.createRequestSecurityTokenElement(version);
        
        TrustUtil.createRequestTypeElement(this.version, rst, requestType);
        
        OMElement tokenTypeElem = TrustUtil.createTokenTypeElement(this.version, rst);
        
        String tokenType =
            TrustUtil.getWSTNamespace(version) + RahasConstants.TOK_TYPE_STATUS;
        
        tokenTypeElem.setText(tokenType);
        
        TokenStorage store = TrustUtil.getTokenStore(configCtx);
        
        Token token = store.getToken(tokenId);
        
        if ( token != null) {            
            OMElement str = token.getUnattachedReference();     
            
            if (str == null) {
                str = token.getAttachedReference();
            }
            
            TrustUtil.createValidateTargetElement(this.version, rst,str);
            
            
        } else {
            throw new TrustException("noToken",new String[]{tokenId});
        }
              
        return rst;
             
    }
    
    private OMElement createRenewRequest(String tokenType, String tokenId) throws TrustException {
        
        String requestType =
            TrustUtil.getWSTNamespace(version) + RahasConstants.REQ_TYPE_RENEW;

        if (log.isDebugEnabled()) {
            log.debug("Creating request with request type: " + requestType);
        }

        OMElement rst = TrustUtil.createRequestSecurityTokenElement(version);
        
        TrustUtil.createRequestTypeElement(this.version, rst, requestType);
        
        OMElement tokenTypeElem = TrustUtil.createTokenTypeElement(version, rst);
        tokenTypeElem.setText(tokenType);
        
        TokenStorage store = TrustUtil.getTokenStore(configCtx);
        
        Token token = store.getToken(tokenId);
        
        if ( token != null) {
            
            OMElement str = token.getUnattachedReference();     
            
            if (str == null) {
                str = token.getAttachedReference();
            }
            
            TrustUtil.createRenewTargetElement(this.version, rst,str);
            
            
        } else {
            throw new TrustException("noToken",new String[]{tokenId});
        }
        
        return rst;
              
        
    }

    private OMElement createCancelRequest(String tokenId) throws TrustException {

        return TrustUtil.createCancelRequest(tokenId, version);
    }

    /**
     * Set this to set the entropy configurations.
     * If this is provided in the given policy it will be overridden.
     *
     * @param trust10 The trust10 to set.
     */
    public void setTrust10(Trust10 trust10) {
        this.trust10 = trust10;
    }
    
    /**
     * Set this to set the entropy configurations.
     * If this is provided in the given policy it will be overridden.
     *
     * @param trust13 The trust13 to set.
     */
    public void setTrust13(Trust13 trust13) {
        this.trust13 = trust13;
    }

    /**
     * This can be used in the case where the AlgorithmSuite is not specified in
     * the given policy.
     * If the AlgorithmSuite exists in a binding in the policy then the value
     * set will be overridden.
     *
     * @param algorithmSuite The algorithmSuite to set.
     */
    public void setAlgorithmSuite(AlgorithmSuite algorithmSuite) {
        this.algorithmSuite = algorithmSuite;
    }

    /**
     * @param addressingNs The addressingNs to set.
     */
    public void setAddressingNs(String addressingNs) {
        this.addressingNs = addressingNs;
    }

    /**
     * @param ttl The ttl to set.
     */
    public void setTtl(int ttl) {
        this.ttl = ttl;
    }

    /**
     * Sets the crypto information required to process the RSTR.
     *
     * @param crypto    Crypto information
     * @param cbHandler Callback handler to provide the private key password to
     *                  decrypt
     */
    public void setCryptoInfo(Crypto crypto, CallbackHandler cbHandler) {
        this.crypto = crypto;
        this.cbHandler = cbHandler;
    }

    /**
     * Sets the crypto information required to process the RSTR.
     *
     * @param crypto        The crypto information
     * @param privKeyPasswd Private key password to decrypt
     */
    public void setCryptoInfo(Crypto crypto, String privKeyPasswd) {
        this.crypto = crypto;
        this.cbHandler = new CBHandler(privKeyPasswd);
    }

    /**
     * @param action The action to set.
     */
    public void setAction(String action) {
        this.action = action;
    }

    /**
     * @param options The options to set.
     */
    public void setOptions(Options options) {
        this.options = options;
    }

    /**
     * @param rstTemplate The rstTemplate to set.
     */
    public void setRstTemplate(OMElement rstTemplate) {
        this.rstTemplate = rstTemplate;
    }

    private static class CBHandler implements CallbackHandler {

        private String passwd;

        private CBHandler(String passwd) {
            this.passwd = passwd;
        }

        public void handle(Callback[] cb) throws IOException,
                                                 UnsupportedCallbackException {
            ((WSPasswordCallback) cb[0]).setPassword(this.passwd);
        }

    }

    /**
     * @param version The version to set.
     */
    public void setVersion(int version) {
        this.version = version;
    }

    public void setSoapVersion(String soapVersion) {
        this.soapVersion = soapVersion;
    }
    
    public void addParameter(Parameter param) {
        parameters.add(param);
    }

}
