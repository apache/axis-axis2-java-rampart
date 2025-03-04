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

package org.apache.rampart;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.OperationContext;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.util.PolicyUtil;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.neethi.Assertion;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyComponent;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.SimpleTokenStore;
import org.apache.rahas.TokenStorage;
import org.apache.rampart.handler.RampartUsernameTokenValidator;
import org.apache.rampart.handler.WSSHandlerConstants;
import org.apache.rampart.policy.RampartPolicyBuilder;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.rampart.saml.SAMLAssertionHandler;
import org.apache.rampart.saml.SAMLAssertionHandlerFactory;
import org.apache.rampart.util.Axis2Util;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.wss4j.policy.SP11Constants;
import org.apache.wss4j.policy.SP12Constants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.SOAPConstants;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSConfig;
import org.apache.wss4j.common.derivedKey.ConversationConstants;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.common.util.Loader;
import org.apache.wss4j.common.util.WSTimeSource;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;
import org.apache.wss4j.dom.message.WSSecHeader;
import org.apache.wss4j.dom.message.token.SecurityContextToken;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.apache.wss4j.dom.engine.WSSecurityEngine;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;

import org.w3c.dom.Document;

import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

public class RampartMessageData {
    
    /**
     * Axis2 parameter name to be used in the client's axis2 xml
     */
    public final static String KEY_RAMPART_POLICY = "rampartPolicy";
    
    public final static String KEY_RAMPART_IN_POLICY = "rampartInPolicy";
        
    public final static String KEY_RAMPART_OUT_POLICY = "rampartOutPolicy";
    
    /**
     * Key to hold the populated RampartPolicyData object
     */
    public final static String RAMPART_POLICY_DATA = "rampartPolicyData";
    
    public final static String RAMPART_STS_POLICY = "rampartStsPolicy";
    
    /**
     * Key to hold the custom issued token identifier
     */
    public final static String KEY_CUSTOM_ISSUED_TOKEN = "customIssuedToken";
    
    /**
     * Key to hold username which was used to authenticate
     */
    public final static String USERNAME = "username";

    /**
     *
     */
    public final static String SIGNATURE_CERT_ALIAS = "signatureCertAlias";

    /**
     * Key to hold the WS-Trust version
     */
    public final static String KEY_WST_VERSION = "wstVersion";
    
    public final static String PARAM_CLIENT_SIDE = "CLIENT_SIDE";

    /**
     * Key to hold the WSTimeSource
     */
    public final static String CUSTOM_WS_TIME_SOURCE = "wsTimeSource";

    /**
     * Key to hold the BSP compliance
     */
    public static final String DISABLE_BSP_ENFORCEMENT = "disableBSPEnforcement";

    public static final String TIMESTAMP_STRICT = "timestampStrict";

    public static final String TIMESTAMP_PRECISION_IN_MS = "timestampPrecisionInMs";

    public final static String ALLOW_USERNAME_TOKEN_NO_PASSWORD = "allowUsernameTokenNoPassword";

    public final static String TIMESTAMP_FUTURE_TTL = "timeStampFutureTTL";

    public final static String UT_TTL = "utTTL";

    public final static String UT_FUTURE_TTL = "utFutureTTL";

    public final static String HANDLE_CUSTOM_PASSWORD_TYPES = "handleCustomPasswordTypes";

    public final static String ALLOW_NAMESPACE_QUALIFIED_PASSWORDTYPES = "allowNamespaceQualifiedPasswordTypes";
    public final static String ENCODE_PASSWORDS = "encodePasswords";

    public final static String VALIDATE_SAML_SUBJECT_CONFIRMATION = "validateSamlSubjectConfirmation";

    public final static String ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM = "allowRSA15KeyTransportAlgorithm";

    /**
     * Key to hold the WS-SecConv version
     */
    public final static String KEY_WSSC_VERSION = "wscVersion";

    public static final String KEY_SCT_ISSUER_POLICY = "sct-issuer-policy";
    
    public final static String CANCEL_REQUEST = "cancelrequest";
    
    public final static String SCT_ID = "sctID";

    public final static String X509_CERT ="X509Certificate";

    public final static String MUST_UNDERSTAND_SECURITY_HEADER = "mustUnderstandSecurityHeader";
    
    private MessageContext msgContext = null;

    private RampartPolicyData policyData = null;

    private WSSecHeader secHeader = null;

    private WSSConfig config = null;
    
    private int timeToLive = 300;
    
    private int timestampMaxSkew = 0;
    
    private String timestampId;
    
    private Document document;

    private TokenStorage tokenStorage;
    
    /**
     * WS-Trust version to use.
     * 
     * Possible values:
     * RahasConstants.VERSION_05_02
     * RahasConstants.VERSION_05_12
     */
    
    private int wstVersion = RahasConstants.VERSION_05_12;
    
    private int secConvVersion = ConversationConstants.VERSION_05_12;
    
    /*
     * IssuedTokens or SecurityContextTokens can be used
     * as the encryption token, signature token
     */
    private String issuedEncryptionTokenId;
    
    private String issuedSignatureTokenId;
    
    /**
     * The service policy extracted from the message context.
     * If policy is specified in the RampartConfig <b>this</b> will take precedence
     */
    private Policy servicePolicy;

    private boolean isInitiator;
    
    private boolean sender;
    
    private ClassLoader customClassLoader;
    
    private SOAPConstants soapConstants;

    public RampartMessageData(MessageContext msgCtx, boolean sender) throws RampartException {
        
        this.msgContext = msgCtx;
        
        try {

            // Set the WSSConfig
            this.config = WSSConfig.getNewInstance();
            
            //Update the UsernameToken validator
            this.config.setValidator(WSConstants.USERNAME_TOKEN, RampartUsernameTokenValidator.class);
            
	    // set the Time Source
            WSTimeSource wsTimeSource = (WSTimeSource)msgCtx.getProperty(CUSTOM_WS_TIME_SOURCE);
            if (wsTimeSource != null) {
                this.config.setCurrentTime(wsTimeSource);
            }

            // First obtain the axis service as we have to do a null check, there can be situations 
            // where Axis Service is null
            AxisService axisService = msgCtx.getAxisService();            
                    
            if(axisService != null && axisService.getParameter(PARAM_CLIENT_SIDE) != null) {
                this.isInitiator = true;
            } else {
                this.isInitiator = !msgCtx.isServerSide();
                //TODO if Axis Service is null at this point, do we have to create a dummy one ??    
                if(this.isInitiator && axisService != null ) {
                    Parameter clientSideParam = new Parameter();
                    clientSideParam.setName(PARAM_CLIENT_SIDE);
                    clientSideParam.setLocked(true);
                    msgCtx.getAxisService().addParameter(clientSideParam);
                }
            }

            if(msgCtx.getProperty(KEY_RAMPART_POLICY) != null) {
                this.servicePolicy = (Policy)msgCtx.getProperty(KEY_RAMPART_POLICY);
            }


            // Checking which flow we are in
            int flow = msgCtx.getFLOW();
            
            // If we are IN flow or IN_FAULT flow and the KEY_RAMPART_IN_POLICY is set , we set the
            // merge that policy to the KEY_RAMPART_POLICY if it is present. Else we set 
            // KEY_RAMPART_IN_POLICY as the service policy
            if ( (flow == MessageContext.IN_FLOW || flow == MessageContext.IN_FAULT_FLOW ) 
                    &&  msgCtx.getProperty(KEY_RAMPART_IN_POLICY) != null) {
                if ( this.servicePolicy == null ) {
                    this.servicePolicy = (Policy)msgCtx.getProperty(KEY_RAMPART_IN_POLICY);
                } else {
                    this.servicePolicy = this.servicePolicy.merge((Policy)msgCtx
                            .getProperty(KEY_RAMPART_IN_POLICY));
                }
                
            // If we are OUT flow or OUT_FAULT flow and the KEY_RAMPART_OUT_POLICY is set , we set 
            // the merge that policy to the KEY_RAMPART_POLICY if it is present. Else we set 
            // KEY_RAMPART_OUT_POLICY as the service policy    
            } else if ( (flow == MessageContext.OUT_FLOW || flow == MessageContext.OUT_FAULT_FLOW ) 
                    &&  msgCtx.getProperty(KEY_RAMPART_OUT_POLICY) != null) {
                if (this.servicePolicy == null) {
                    this.servicePolicy = (Policy)msgCtx.getProperty(KEY_RAMPART_OUT_POLICY);
                } else {
                    this.servicePolicy = this.servicePolicy.merge((Policy)msgCtx
                            .getProperty(KEY_RAMPART_OUT_POLICY));
                }
            }
            
            /*
             * Init policy:
             * When creating the RampartMessageData instance we 
             * extract the service policy is set in the msgCtx.
             * If it is missing then try to obtain from the configuration files.
             */

            if (this.servicePolicy == null) {
                try {
                    this.servicePolicy = msgCtx.getEffectivePolicy();
                } catch (NullPointerException e) {
                    //TODO remove this once AXIS2-4114 is fixed
                    if (axisService != null) {
                        Collection<PolicyComponent> policyList = new ArrayList<PolicyComponent>();
                        policyList.addAll(axisService.getPolicySubject().getAttachedPolicyComponents());
                        AxisConfiguration axisConfiguration = axisService.getAxisConfiguration();
                        policyList.addAll(axisConfiguration.getPolicySubject().getAttachedPolicyComponents());
                        this.servicePolicy = PolicyUtil.getMergedPolicy(policyList, axisService);
                    }
                }
            }

            if(this.servicePolicy == null) {
                Parameter param = msgCtx.getParameter(RampartMessageData.KEY_RAMPART_POLICY);
                if(param != null) {
                    OMElement policyElem = param.getParameterElement().getFirstElement();
                    this.servicePolicy = PolicyEngine.getPolicy(policyElem);
                }
            }
            
            if(this.servicePolicy != null){
                List<Assertion> it = this.servicePolicy.getAlternatives().next();

                //Process policy and build policy data
                this.policyData = RampartPolicyBuilder.build(it);

                //Set the version
                setWSSecurityVersions(this.policyData.getWebServiceSecurityPolicyNS());
            }

            
            if(this.policyData != null) {

                // Get the SOAP envelope as document, then create a security
                // header and insert into the document (Envelope)
                // WE SHOULD ONLY DO THE CONVERTION IF THERE IS AN APPLICABLE POLICY
                this.document = Axis2Util.getDocumentFromSOAPEnvelope(msgCtx.getEnvelope(), true);
                msgCtx.setEnvelope((SOAPEnvelope)this.document.getDocumentElement());

                this.soapConstants = WSSecurityUtil.getSOAPConstants(this.document.getDocumentElement());

                // Update the Rampart Config if RampartConfigCallbackHandler is present in the
                // RampartConfig
                
                RampartConfigCallbackHandler rampartConfigCallbackHandler = RampartUtil
                        .getRampartConfigCallbackHandler(msgCtx, policyData);
                
                if (rampartConfigCallbackHandler != null) {
                    rampartConfigCallbackHandler.update(policyData.getRampartConfig());
                }

                // Update TTL and max skew time
                RampartConfig policyDataRampartConfig = policyData.getRampartConfig();
                if (policyDataRampartConfig != null) {
                    String timeToLiveString = policyDataRampartConfig.getTimestampTTL();
                    if (timeToLiveString != null && !timeToLiveString.equals("")) {
                        this.setTimeToLive(Integer.parseInt(timeToLiveString));
                    }

                    String maxSkewString = policyDataRampartConfig.getTimestampMaxSkew();
                    if (maxSkewString != null && !maxSkewString.equals("")) {
                        this.setTimestampMaxSkew(Integer.parseInt(maxSkewString));
                    }
                }
                
                //Check for RST and RSTR for an SCT
                String wsaAction = msgContext.getWSAAction();
                if(WSSHandlerConstants.RST_ACTON_SCT.equals(wsaAction)
                        || WSSHandlerConstants.RSTR_ACTON_SCT.equals(wsaAction)) {
                    //submissive version
                    setTrustParameters();
                }else if(WSSHandlerConstants.RST_ACTON_SCT_STANDARD.equals(wsaAction)
                        || WSSHandlerConstants.RSTR_ACTON_SCT_STANDARD.equals(wsaAction)) {
                    //standard policy spec 1.2
                    setTrustParameters();
                }
            }
            
            
            this.sender = sender;
            
            OperationContext opCtx = this.msgContext.getOperationContext();
            
            if(!this.isInitiator && this.sender) {
                //Get hold of the incoming msg ctx
                MessageContext inMsgCtx;
                if (opCtx != null
                        && (inMsgCtx = opCtx
                                .getMessageContext(WSDLConstants.MESSAGE_LABEL_IN_VALUE)) != null
                                && msgContext.getProperty(WSHandlerConstants.RECV_RESULTS) == null) {
                    msgContext.setProperty(WSHandlerConstants.RECV_RESULTS, 
                            inMsgCtx.getProperty(WSHandlerConstants.RECV_RESULTS));
                    
                    //If someone set the sct_id externally use it at the receiver
                    msgContext.setProperty(SCT_ID, inMsgCtx.getProperty(SCT_ID));
                }
            }
            
            if(this.isInitiator && !this.sender) {
                MessageContext outMsgCtx;
                if (opCtx != null
                        && (outMsgCtx = opCtx
                                .getMessageContext(WSDLConstants.MESSAGE_LABEL_OUT_VALUE)) != null) {
                    
                    //If someone set the sct_id externally use it at the receiver
                    msgContext.setProperty(SCT_ID, outMsgCtx.getProperty(SCT_ID));
                }
            }

            // Check whether RampartConfig is present
            if (this.policyData != null && this.policyData.getRampartConfig() != null) {

		// set some vars on WSS4J class RequestData via RamparConfig as desired in 
		// Jira issues RAMPART-205, RAMPART-361, RAMPART-432, RAMPART-435
	        // The precedence is MessageContext wins

                Boolean timestampPrecisionInMsInput = (Boolean)msgCtx.getProperty(TIMESTAMP_PRECISION_IN_MS);
                if (timestampPrecisionInMsInput != null) {
                    this.policyData.getRampartConfig().setDefaultTimestampPrecisionInMs(timestampPrecisionInMsInput);
                }

                Boolean timestampStrictInput = (Boolean)msgCtx.getProperty(TIMESTAMP_STRICT);
                if (timestampStrictInput != null) {
                    this.policyData.getRampartConfig().setTimeStampStrict(timestampStrictInput);
                }

		// 1.8.0 and later
                Boolean disableBSPEnforcementInput = (Boolean)msgCtx.getProperty(DISABLE_BSP_ENFORCEMENT);
                if (disableBSPEnforcementInput != null) {
                    this.policyData.getRampartConfig().setDisableBSPEnforcement(disableBSPEnforcementInput);
                }
                Boolean handleCustomPasswordTypesInput = (Boolean)msgCtx.getProperty(HANDLE_CUSTOM_PASSWORD_TYPES);
                if (handleCustomPasswordTypesInput != null) {
                    this.policyData.getRampartConfig().setHandleCustomPasswordTypes(handleCustomPasswordTypesInput);
                }
                Boolean allowNamespaceQualifiedPasswordTypesInput = (Boolean)msgCtx.getProperty(ALLOW_NAMESPACE_QUALIFIED_PASSWORDTYPES);
                if (allowNamespaceQualifiedPasswordTypesInput != null) {
                    this.policyData.getRampartConfig().setAllowNamespaceQualifiedPasswordTypes(allowNamespaceQualifiedPasswordTypesInput);
                }
                Boolean allowUsernameTokenNoPasswordInput = (Boolean)msgCtx.getProperty(ALLOW_USERNAME_TOKEN_NO_PASSWORD);
                if (allowUsernameTokenNoPasswordInput != null) {
                    this.policyData.getRampartConfig().setAllowUsernameTokenNoPassword(allowUsernameTokenNoPasswordInput);
                }
                Boolean allowRSA15KeyTransportAlgorithmInput = (Boolean)msgCtx.getProperty(ALLOW_RSA15_KEY_TRANSPORT_ALGORITHM);
                if (allowRSA15KeyTransportAlgorithmInput != null) {
                    this.policyData.getRampartConfig().setAllowRSA15KeyTransportAlgorithm(allowRSA15KeyTransportAlgorithmInput);
                }
                Integer timeStampFutureTTLInput = (Integer)msgCtx.getProperty(TIMESTAMP_FUTURE_TTL);
                if (timeStampFutureTTLInput != null) {
                    this.policyData.getRampartConfig().setTimeStampFutureTTL(timeStampFutureTTLInput);
                }
                Integer utTTLInput = (Integer)msgCtx.getProperty(UT_TTL);
                if (utTTLInput != null) {
                    this.policyData.getRampartConfig().setUtTTL(utTTLInput);
                }
                Integer utFutureTTLInput = (Integer)msgCtx.getProperty(UT_FUTURE_TTL);
                if (utFutureTTLInput != null) {
                    this.policyData.getRampartConfig().setUtFutureTTL(utFutureTTLInput);
                }

            }

            if (axisService != null) { 
                this.customClassLoader = axisService.getClassLoader(); 
            } 
            
            if(this.sender && this.policyData != null) {
                this.secHeader = new WSSecHeader(this.document);
                secHeader.insertSecurityHeader();
		// RAMPART-261
                Boolean mustUnderstandSecurityHeaderInput = (Boolean)msgCtx.getProperty(MUST_UNDERSTAND_SECURITY_HEADER);
                if (mustUnderstandSecurityHeaderInput != null) {
                    secHeader.setMustUnderstand(mustUnderstandSecurityHeaderInput);
                } else if (this.policyData != null && this.policyData.getRampartConfig() != null) {
                    secHeader.setMustUnderstand(this.policyData.getRampartConfig().isMustUnderstandSecurityHeader());
		}
            }
            
        } catch (AxisFault e) {
            throw new RampartException("errorInExtractingMsgProps", e);
        } catch (WSSPolicyException e) {
            throw new RampartException("errorInExtractingMsgProps", e);
        } catch (WSSecurityException e) {
            throw new RampartException("errorInExtractingMsgProps", e);
        }
        
    }

    private void setWSSecurityVersions(String namespace) throws RampartException {

        if (namespace == null || namespace.equals("")) {
            throw new RampartException("securityPolicyNamespaceCannotBeNull");
        }

        if (SP11Constants.SP_NS.equals(namespace)) {
            this.wstVersion = RahasConstants.VERSION_05_02;
            this.secConvVersion = ConversationConstants.VERSION_05_02;
        } else if (SP12Constants.SP_NS.equals(namespace)) {
            this.wstVersion = RahasConstants.VERSION_05_12;
            this.secConvVersion = ConversationConstants.VERSION_05_12;
        } else {
            throw new RampartException("Invalid namespace received, " + namespace);
        }

    }

    private void setTrustParameters() throws RampartException {

        if (this.policyData.getIssuerPolicy() == null) {
            return;
        }

        this.servicePolicy = this.policyData.getIssuerPolicy();

        RampartConfig rampartConfig = policyData.getRampartConfig();
        if (rampartConfig != null) {
            /*
            * Copy crypto info into the new issuer policy
            */
            RampartConfig rc = new RampartConfig();
            rc.setEncrCryptoConfig(rampartConfig.getEncrCryptoConfig());
            rc.setSigCryptoConfig(rampartConfig.getSigCryptoConfig());
            rc.setDecCryptoConfig(rampartConfig.getDecCryptoConfig());
            rc.setUser(rampartConfig.getUser());
            rc.setUserCertAlias(rc.getUserCertAlias());
            rc.setEncryptionUser(rampartConfig.getEncryptionUser());
            rc.setPwCbClass(rampartConfig.getPwCbClass());
            rc.setSSLConfig(rampartConfig.getSSLConfig());

            this.servicePolicy.addAssertion(rc);
        }

        List<Assertion> it = this.servicePolicy.getAlternatives().next();

        //Process policy and build policy data
        try {
            this.policyData = RampartPolicyBuilder.build(it);
        } catch (WSSPolicyException e) {
            throw new RampartException("errorInExtractingMsgProps", e);
        }

    }

    /**
     * @return Returns the document.
     */
    public Document getDocument() {
        return document;
    }

    /**
     * @return Returns the timeToLive.
     */
    public int getTimeToLive() {
        return timeToLive;
    }

    /**
     * @param timeToLive The timeToLive to set.
     */
    public void setTimeToLive(int timeToLive) {
        this.timeToLive = timeToLive;
    }

    /**
     * @return Returns the timestampMaxSkew.
     */
    public int getTimestampMaxSkew() {
        return timestampMaxSkew;
    }

    /**
     * @param timestampMaxSkew The timestampMaxSkew to set.
     */
    public void setTimestampMaxSkew(int timestampMaxSkew) {
        this.timestampMaxSkew = timestampMaxSkew;
    }

    /**
     * @return Returns the config.
     */
    public WSSConfig getConfig() {
        return config;
    }

    /**
     * @param config
     *            The config to set.
     */
    public void setConfig(WSSConfig config) {
        this.config = config;
    }

    /**
     * @return Returns the msgContext.
     */
    public MessageContext getMsgContext() {
        return msgContext;
    }

    /**
     * @return Returns the policyData.
     */
    public RampartPolicyData getPolicyData() {
        return policyData;
    }

    /**
     * @return Returns the secHeader.
     */
    public WSSecHeader getSecHeader() {
        return secHeader;
    }

    /**
     * @param secHeader
     *            The secHeader to set.
     */
    public void setSecHeader(WSSecHeader secHeader) {
        this.secHeader = secHeader;
    }

    /**
     * @return Returns the issuedEncryptionTokenId.
     */
    public String getIssuedEncryptionTokenId() {
        return issuedEncryptionTokenId;
    }

    /**
     * @param issuedEncryptionTokenId The issuedEncryptionTokenId to set.
     */
    public void setIssuedEncryptionTokenId(String issuedEncryptionTokenId) {
        this.issuedEncryptionTokenId = issuedEncryptionTokenId;
    }

    /**
     * @return Returns the issuedSignatureTokenId.
     */
    public String getIssuedSignatureTokenId() {
        if(this.isInitiator) {
            return issuedSignatureTokenId;
        } else {
            //Pick the first SAML token
            //TODO : This is a hack , MUST FIX
            //get the sec context id from the req msg ctx
            List<WSHandlerResult> results
                    = (List<WSHandlerResult>)this.msgContext.getProperty(WSHandlerConstants.RECV_RESULTS);
            for (WSHandlerResult result : results) {
                List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();

                for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                    final Integer actInt =
                            (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                    if (WSConstants.ST_UNSIGNED == actInt) {
                        final Object assertion =
                                wsSecEngineResult.get(WSSecurityEngineResult.TAG_SAML_ASSERTION);
                        SAMLAssertionHandler samlAssertionHandler
                                = SAMLAssertionHandlerFactory.createAssertionHandler(assertion);

                        return samlAssertionHandler.getAssertionId();
                    }

                }
            }
            return null;
        }
    }

    /**
     * @param issuedSignatureTokenId The issuedSignatureTokenId to set.
     */
    public void setIssuedSignatureTokenId(String issuedSignatureTokenId) {
        this.issuedSignatureTokenId = issuedSignatureTokenId;
    }

    /**
     * @return Returns the secConvTokenId.
     */
    public String getSecConvTokenId() {
        String id = null;
        
        if(this.isInitiator) {
            String contextIdentifierKey = RampartUtil.getContextIdentifierKey(this.msgContext);
            id = (String) RampartUtil.getContextMap(this.msgContext).get(contextIdentifierKey);
        } else {
            //get the sec context id from the req msg ctx
            List<WSHandlerResult> results = (List<WSHandlerResult>)this.msgContext.getProperty(WSHandlerConstants.RECV_RESULTS);
            for (WSHandlerResult result : results) {
                List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();

                for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                    final Integer actInt =
                            (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                    if (WSConstants.SCT == actInt) {
                        final SecurityContextToken sct =
                                ((SecurityContextToken) wsSecEngineResult
                                        .get(WSSecurityEngineResult.TAG_SECURITY_CONTEXT_TOKEN));
                        id = sct.getID();
                    }

                }
            }
        }

        if(id == null || id.length() == 0) {
            //If we can't find the sec conv token id up to this point then
            //check if someone has specified which one to use
            id = (String)this.msgContext.getProperty(SCT_ID);
        }
        
        return id;
    }

    /**
     * @param secConvTokenId The secConvTokenId to set.
     */
    public void setSecConvTokenId(String secConvTokenId) {
        String contextIdentifierKey = RampartUtil.getContextIdentifierKey(this.msgContext);
        RampartUtil.getContextMap(this.msgContext).put(
                                                    contextIdentifierKey,
                                                    secConvTokenId);
    }



    /**
     * @return Returns the tokenStorage.
     * @throws RampartException If an error occurs getting TokenStorage
     */
    public TokenStorage getTokenStorage() throws RampartException {

        if(this.tokenStorage != null) {
            return this.tokenStorage;
        }

        TokenStorage storage = (TokenStorage) this.msgContext.getConfigurationContext().getProperty(
                        TokenStorage.TOKEN_STORAGE_KEY);

        if (storage != null) {
            this.tokenStorage = storage;
        } else {
            if (this.policyData.getRampartConfig() != null &&
                    this.policyData.getRampartConfig().getTokenStoreClass() != null) {
                Class stClass = null;
                String storageClass = this.policyData.getRampartConfig()
                        .getTokenStoreClass();
                try {
                    stClass = Loader.loadClass(this.customClassLoader, storageClass);
                } catch (ClassNotFoundException e) {
                    throw new RampartException(
                            "WSHandler: cannot load token storage class: "
                                    + storageClass, e);
                }
                try {
                    this.tokenStorage = (TokenStorage) stClass.newInstance();
                } catch (java.lang.Exception e) {
                    throw new RampartException(
                            "Cannot create instance of token storage: "
                                    + storageClass, e);
                }
            } else {
                this.tokenStorage = new SimpleTokenStore();
                
            }
            
            //Set the storage instance
            this.msgContext.getConfigurationContext().setProperty(
                    TokenStorage.TOKEN_STORAGE_KEY, this.tokenStorage);
        }
        
        
        return tokenStorage;
    }

    /**
     * @param tokenStorage The tokenStorage to set.
     */
    public void setTokenStorage(TokenStorage tokenStorage) {
        this.tokenStorage = tokenStorage;
    }

    /**
     * @return Returns the wstVersion.
     */
    public int getWstVersion() {
        return wstVersion;
    }

    /**
     * @return Returns the secConvVersion.
     */
    public int getSecConvVersion() {
        return secConvVersion;
    }

    /**
     * @return Returns the servicePolicy.
     */
    public Policy getServicePolicy() {
        return servicePolicy;
    }

    
    /**
     * @return Returns the timestampId.
     */
    public String getTimestampId() {
        return timestampId;
    }

    /**
     * @param timestampId The timestampId to set.
     */
    public void setTimestampId(String timestampId) {
        this.timestampId = timestampId;
    }

    /**
     * @return Returns the Initiator value
     */
    public boolean isInitiator() {
        return isInitiator;
    }

    /**
     * Returns the custom class loader if we are using one
     * @return Returns the custom class loader if we are using one
     */
    public ClassLoader getCustomClassLoader() {
        return customClassLoader;
    }

    /**
     * Returns an <code>org.apache.ws.security.SOAPConstants</code> instance 
     * with soap version information of this request. 
     * @return Returns soap version information of this request
     */
    public SOAPConstants getSoapConstants() {
        return soapConstants;
    }
}
