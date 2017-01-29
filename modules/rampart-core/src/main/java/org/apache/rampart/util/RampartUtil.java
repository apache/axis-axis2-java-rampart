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

package org.apache.rampart.util;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMAttribute;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.axiom.soap.*;
import org.apache.axis2.AxisFault;
import org.apache.axis2.addressing.AddressingConstants;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.dataretrieval.DRConstants;
import org.apache.axis2.dataretrieval.client.MexClient;
import org.apache.axis2.description.AxisService;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.description.TransportInDescription;
import org.apache.axis2.engine.AxisConfiguration;
import org.apache.axis2.mex.MexConstants;
import org.apache.axis2.mex.MexException;
import org.apache.axis2.mex.om.Metadata;
import org.apache.axis2.mex.om.MetadataReference;
import org.apache.axis2.mex.om.MetadataSection;
import org.apache.axis2.transport.TransportListener;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.httpclient.protocol.Protocol;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.neethi.Policy;
import org.apache.neethi.PolicyEngine;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.Token;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.client.STSClient;
import org.apache.rampart.PolicyBasedResultsValidator;
import org.apache.rampart.PolicyValidatorCallbackHandler;
import org.apache.rampart.RampartConfigCallbackHandler;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartException;
import org.apache.rampart.RampartMessageData;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.policy.model.CryptoConfig;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.*;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSEncryptionPart;
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSConfig;
import org.apache.ws.security.WSSecurityEngineResult;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.WSUsernameTokenPrincipal;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.apache.ws.security.conversation.ConversationConstants;
import org.apache.ws.security.conversation.ConversationException;
import org.apache.ws.security.handler.WSHandlerConstants;
import org.apache.ws.security.handler.WSHandlerResult;
import org.apache.ws.security.message.WSSecBase;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.util.Loader;
import org.apache.ws.security.util.WSSecurityUtil;
import org.apache.ws.security.validate.KerberosTokenDecoder;
import org.apache.xml.security.utils.Constants;
import org.jaxen.JaxenException;
import org.jaxen.XPath;
import org.w3c.dom.Document;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

import javax.crypto.KeyGenerator;
import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.namespace.QName;
import javax.servlet.http.HttpServletRequest;

import java.security.NoSuchAlgorithmException;
import java.security.cert.X509Certificate;
import java.util.*;
import java.util.concurrent.ConcurrentHashMap;

public class RampartUtil {

    private static final String CRYPTO_PROVIDER = "org.apache.ws.security.crypto.provider";
    private static Log log = LogFactory.getLog(RampartUtil.class);

    private static Map<String, CachedCrypto> cryptoStore = new ConcurrentHashMap<String, CachedCrypto>();

    private static class CachedCrypto {
        private Crypto crypto;
        private long creationTime;

        public CachedCrypto(Crypto crypto, long creationTime) {
            this.crypto = crypto;
            this.creationTime = creationTime;
        }
    }

    public static CallbackHandler getPasswordCB(RampartMessageData rmd) throws RampartException {

        MessageContext msgContext = rmd.getMsgContext();
        RampartPolicyData rpd = rmd.getPolicyData();
        
        return getPasswordCB(msgContext, rpd);
    }

    /**
     * @param msgContext
     * @param rpd
     * @return The <code>CallbackHandler</code> instance
     * @throws RampartException
     */
    public static CallbackHandler getPasswordCB(MessageContext msgContext, RampartPolicyData rpd) throws RampartException {
        
        CallbackHandler cbHandler;

        if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getPwCbClass() != null) {
            
            String cbHandlerClass = rpd.getRampartConfig().getPwCbClass();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

            if (log.isDebugEnabled()) {
                log.debug("loading class : " + cbHandlerClass);
            }

            Class cbClass;
            try {
                cbClass = Loader.loadClass(classLoader, cbHandlerClass);
            } catch (ClassNotFoundException e) {
                throw new RampartException("cannotLoadPWCBClass", 
                        new String[]{cbHandlerClass}, e);
            }
            try {
                cbHandler = (CallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new RampartException("cannotCreatePWCBInstance",
                        new String[]{cbHandlerClass}, e);
            }
        } else {
            cbHandler = (CallbackHandler) msgContext.getProperty(
                    WSHandlerConstants.PW_CALLBACK_REF);
            if(cbHandler == null) {
                Parameter param = msgContext.getParameter(
                        WSHandlerConstants.PW_CALLBACK_REF);
                if(param != null) {
                    cbHandler = (CallbackHandler)param.getValue();
                }
            }
        }
        
        return cbHandler;
    }
    
    /**
     * Instantiates any Kerberos token decoder implementation configured via {@link KerberosConfig#setKerberosTokenDecoderClass(String)}
     * using the {@link AxisService#getClassLoader() class loader} of the specified message context's {@link MessageContext#getAxisService() service}.
     * 
     * @param msgContext The current message context. Must not be null and must contain a valid service instance.
     * @param kerberosConfig Rampart's Kerberos configuration.
     * 
     * @return A new instance of {@link KerberosTokenDecoder} implementation configured via {@link KerberosConfig#setKerberosTokenDecoderClass(String)} or <code>null</code>
     * if no Kerberos token decoder is configured.
     * @throws RampartException If the class cannot be loaded or instantiated.
     */
    public static KerberosTokenDecoder getKerberosTokenDecoder(MessageContext msgContext, KerberosConfig kerberosConfig) throws RampartException {
        if (kerberosConfig == null) {
            throw new IllegalArgumentException("Kerberos config must not be null");
        }
        else if (msgContext == null) {
            throw new IllegalArgumentException("Message context must not be null");
        }
        
        AxisService service = msgContext.getAxisService();
        if (service == null) {
            throw new IllegalArgumentException("No service available in message context: " + msgContext.getLogIDString());
        }
        
        KerberosTokenDecoder kerberosTokenDecoder;
        
        String kerberosTokenDecoderClass = kerberosConfig.getKerberosTokenDecoderClass();
        if (kerberosTokenDecoderClass == null) {
            if (log.isDebugEnabled()) {
                log.debug("No Kerberos token decoder class configured for service: " + service.getName());
            }
            return null;
        }

        if (log.isDebugEnabled()) {
            log.debug(String.format("Loading Kerberos token decoder class '%s' using class loader of service '%s'", kerberosTokenDecoderClass, service.getName()));
        }
        
        ClassLoader classLoader = service.getClassLoader();
        Class krbTokenDecoderClass;
        try {
            krbTokenDecoderClass = Loader.loadClass(classLoader, kerberosTokenDecoderClass);
        } 
        catch (ClassNotFoundException e) {
            throw new RampartException("cannotLoadKrbTokenDecoderClass", 
                    new String[] { kerberosTokenDecoderClass }, e);
        }
        
        try {
            kerberosTokenDecoder = (KerberosTokenDecoder) krbTokenDecoderClass.newInstance();
        } catch (java.lang.Exception e) {
            throw new RampartException("cannotCreateKrbTokenDecoderInstance",
                    new String[] { kerberosTokenDecoderClass }, e);
        }

        return kerberosTokenDecoder;
    }
    
   /**
    * Returns an instance of PolicyValidatorCallbackHandler to be used to validate ws-security results.
    * 
    * @param msgContext {@link MessageContext}
    * @param rpd {@link RampartPolicyData}
    * @return {@link PolicyValidatorCallbackHandler}
    * @throws RampartException RampartException
    */ 
   public static PolicyValidatorCallbackHandler getPolicyValidatorCB(MessageContext msgContext, RampartPolicyData rpd) throws RampartException {
        
       PolicyValidatorCallbackHandler cbHandler;

        if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getPolicyValidatorCbClass() != null) {
            
            String cbHandlerClass = rpd.getRampartConfig().getPolicyValidatorCbClass();
            ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

            if (log.isDebugEnabled()) {
                log.debug("loading class : " + cbHandlerClass);
            }

            Class cbClass;
            try {
                cbClass = Loader.loadClass(classLoader, cbHandlerClass);
            } catch (ClassNotFoundException e) { 
                throw new RampartException("cannotLoadPolicyValidatorCbClass", 
                        new String[]{cbHandlerClass}, e);
            }
            try {
                cbHandler = (PolicyValidatorCallbackHandler) cbClass.newInstance();
            } catch (java.lang.Exception e) {
                throw new RampartException("cannotCreatePolicyValidatorCallbackInstance",
                        new String[]{cbHandlerClass}, e);
            }
            
        } else { // Initialise default PolicyValidatorCallbackHandler...
            cbHandler = new PolicyBasedResultsValidator();
        }
        
        return cbHandler;
    }
   
   public static RampartConfigCallbackHandler getRampartConfigCallbackHandler(MessageContext msgContext, 
           RampartPolicyData rpd) throws RampartException {
       
       RampartConfigCallbackHandler rampartConfigCB;
   
       if (rpd.getRampartConfig() != null && rpd.getRampartConfig().getRampartConfigCbClass() != null) {
           
           String cbHandlerClass = rpd.getRampartConfig().getRampartConfigCbClass();
           ClassLoader classLoader = msgContext.getAxisService().getClassLoader();

           if (log.isDebugEnabled()) {
               log.debug("loading class : " + cbHandlerClass);
           }

           Class cbClass;
           try {
               cbClass = Loader.loadClass(classLoader, cbHandlerClass);
           } catch (ClassNotFoundException e) {
               throw new RampartException("cannotLoadRampartConfigCallbackClass", 
                       new String[]{cbHandlerClass}, e);
           }
           try {
               rampartConfigCB = (RampartConfigCallbackHandler) cbClass.newInstance();
           } catch (java.lang.Exception e) {
               throw new RampartException("cannotCreateRampartConfigCallbackInstance",
                       new String[]{cbHandlerClass}, e);
           }
           
           return rampartConfigCB;
           
       }
       
       return null;
   }

    /**
     * Perform a callback to get a password.
     * <p/>
     * The called back function gets an indication why to provide a password:
     * to produce a UsernameToken, Signature, or a password (key) for a given
     * name.
     */
    public static WSPasswordCallback performCallback(CallbackHandler cbHandler,
                                               String username,
                                               int doAction)
            throws RampartException {

        WSPasswordCallback pwCb;
        int reason = 0;

        switch (doAction) {
        case WSConstants.UT:
        case WSConstants.UT_SIGN:
                reason = WSPasswordCallback.USERNAME_TOKEN;
                break;
            case WSConstants.SIGN:
                reason = WSPasswordCallback.SIGNATURE;
                break;
            case WSConstants.ENCR:
                reason = WSPasswordCallback.KEY_NAME;
                break;
        }
        pwCb = new WSPasswordCallback(username, reason);
        Callback[] callbacks = new Callback[1];
        callbacks[0] = pwCb;
        /*
        * Call back the application to get the password
        */
        try {
            cbHandler.handle(callbacks);
        } catch (Exception e) {
            throw new RampartException("pwcbFailed", e);
        }
        return pwCb;
    }
    
    /**
     * Create the <code>Crypto</code> instance for encryption using information 
     * from the rampart configuration assertion
     * 
     * @param config
     * @return The <code>Crypto</code> instance to be used for encryption
     * @throws RampartException
     */
    public static Crypto getEncryptionCrypto(RampartConfig config, ClassLoader loader)
            throws RampartException {

        log.debug("Loading encryption crypto");

        Crypto crypto = null;

        if (config != null && config.getEncrCryptoConfig() != null) {
            CryptoConfig cryptoConfig = config.getEncrCryptoConfig();
            String provider = cryptoConfig.getProvider();
            if (log.isDebugEnabled()) {
                log.debug("Using provider: " + provider);
            }
            Properties prop = cryptoConfig.getProp();
            prop.put(CRYPTO_PROVIDER, provider);

            String cryptoKey = null;
            String interval = null;
            if (cryptoConfig.isCacheEnabled()) {
                if (cryptoConfig.getCryptoKey() != null) {
                    cryptoKey = prop.getProperty(cryptoConfig.getCryptoKey());
                    interval = cryptoConfig.getCacheRefreshInterval();
                }
                else if(provider.equals(RampartConstants.MERLIN_CRYPTO_IMPL)){
                    cryptoKey = cryptoConfig.getProp().getProperty(RampartConstants.MERLIN_CRYPTO_IMPL_CACHE_KEY);
                }
            }


            if (cryptoKey != null) {
                // Crypto caching is enabled
                crypto = retrieveCryptoFromCache(cryptoKey.trim() + "#" + provider.trim(), interval);
            }

            if (crypto == null) {
                // cache miss
                crypto = createCrypto(prop, loader);

                if (cryptoKey != null) {
                    // Crypto caching is enabled - cache the Crypto object
                    cacheCrypto(cryptoKey.trim() + "#" + provider.trim(), crypto);
                }
            }
        } else {
            log.debug("Trying the signature crypto info");
            crypto = getSignatureCrypto(config, loader);
        }
        return crypto;
    }

    private static Crypto createCrypto(Properties properties, ClassLoader classLoader) throws RampartException {

        try {
            return CryptoFactory.getInstance(properties, classLoader);
        } catch (WSSecurityException e) {
            log.error("Error loading crypto properties.", e);
            throw new RampartException("cannotCrateCryptoInstance", e);
        }
    }
    
    /**
     * Create the <code>Crypto</code> instance for signature using information 
     * from the rampart configuration assertion
     * 
     * @param config
     * @return The <code>Crypto</code> instance to be used for signature
     * @throws RampartException
     */
    public static Crypto getSignatureCrypto(RampartConfig config, ClassLoader loader)
            throws RampartException {

        log.debug("Loading Signature crypto");

        Crypto crypto = null;

        if (config != null && config.getSigCryptoConfig() != null) {
            CryptoConfig cryptoConfig = config.getSigCryptoConfig();
            String provider = cryptoConfig.getProvider();
            if (log.isDebugEnabled()) {
                log.debug("Using provider: " + provider);
            }
            Properties prop = cryptoConfig.getProp();
            prop.put(CRYPTO_PROVIDER, provider);
            String cryptoKey = null;
            String interval = null;

            if (cryptoConfig.isCacheEnabled()) {
                if (cryptoConfig.getCryptoKey() != null) {
                    cryptoKey = prop.getProperty(cryptoConfig.getCryptoKey());
                    interval = cryptoConfig.getCacheRefreshInterval();
                }
                else if(provider.equals(RampartConstants.MERLIN_CRYPTO_IMPL)){
                    cryptoKey = cryptoConfig.getProp().getProperty(RampartConstants.MERLIN_CRYPTO_IMPL_CACHE_KEY);
                }
            }

            if (cryptoKey != null) {
                // cache enabled
                crypto = retrieveCryptoFromCache(cryptoKey.trim() + "#" + provider.trim(), interval);
            }

            if (crypto == null) {
                // cache miss
                crypto = createCrypto(prop, loader);
                if (cryptoKey != null) {
                    // cache enabled - let's cache
                    cacheCrypto(cryptoKey.trim() + "#" + provider.trim(), crypto);
                }
            }
        }
        return crypto;
    }
    
    
    /**
     * figureout the key identifier of a give X509Token
     * @param token
     * @return The key identifier of a give X509Token
     * @throws RampartException
     */
    public static int getKeyIdentifier(X509Token token) throws RampartException {
        if (token.isRequireIssuerSerialReference()) {
            return WSConstants.ISSUER_SERIAL;
        } else if (token.isRequireThumbprintReference()) {
            return WSConstants.THUMBPRINT_IDENTIFIER;
        } else if (token.isRequireEmbeddedTokenReference()) {
            return WSConstants.BST_DIRECT_REFERENCE;
        } else {
            throw new RampartException(
                    "unknownKeyRefSpeficier");

        }
    }
    
    /**
     * Process a give issuer address element and return the address.
     * @param issuerAddress
     * @return The address of an issuer address element
     * @throws RampartException If the issuer address element is malformed.
     */
    public static String processIssuerAddress(OMElement issuerAddress) 
        throws RampartException {

    	if(issuerAddress == null){
    		throw new RampartException("invalidIssuerAddress", 
    		                           new String[] { "Issuer address null" });
    	}
    	
    	if(issuerAddress.getText() == null || "".equals(issuerAddress.getText())) {
    		throw new RampartException("invalidIssuerAddress", 
    		                           new String[] { issuerAddress.toString() });
        }

    	return issuerAddress.getText().trim();
    }
    
    /**
     * Retrieve policy using metadata reference 
     * <wsa:Metadata xmlns:wsa="http://www.w3.org/2005/08/addressing">
     *  <mex:Metadata
     *       xmlns:mex="http://schemas.xmlsoap.org/ws/2004/09/mex"
     *       xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance">
     *           <mex:MetadataSection>
     *                  <mex:MetadataReference>
     *                      <wsa:Address>http://address/of/mex/service</wsa:Address>
     *                  </mex:MetadataReference>
     *           </mex:MetadataSection>
     *  </mex:Metadata>
     * </wsa:Metadata>
     * @param mex Metadata element 
     * @return Policy from the mex service
     */
    public static Policy getPolicyFromMetadataRef(OMElement mex) throws RampartException {
        
        try {
            Metadata metadata = new Metadata();
            metadata.fromOM(mex.getFirstElement());
            
            MetadataSection[] metadataSections = metadata.getMetadatSections();
            MetadataReference reference = metadataSections[0].getMetadataReference();
            
            MexClient serviceClient = new MexClient();

            Options options = serviceClient.getOptions();
            options.setTo(reference.getEPR());
            options.setAction(DRConstants.SPEC.Actions.GET_METADATA_REQUEST);
            
            OMElement request = serviceClient.setupGetMetadataRequest(
                                                        MexConstants.SPEC.DIALECT_TYPE_POLICY,null);
            OMElement result = serviceClient.sendReceive(request);
            
            metadata.fromOM(result);
            MetadataSection[] mexSecs =  metadata.getMetadataSection(MexConstants.SPEC.DIALECT_TYPE_POLICY, null);
            OMElement policyElement = (OMElement) mexSecs[0].getInlineData();
            
            return PolicyEngine.getPolicy(policyElement);
            
            
        } catch (MexException e) {
            throw new RampartException("Error Retrieving the policy from mex", e);
        } catch (AxisFault e) {
            throw new RampartException("Error Retrieving the policy from mex", e);
        }
        
    }
    
    public static Policy addRampartConfig (RampartMessageData rmd, Policy policy) {
        
        RampartConfig servicRampConf = rmd.getPolicyData().getRampartConfig();        
        RampartConfig stsRampConf = new RampartConfig();
        
        //TODO copy all the properties of service ramp conf to sts ramp conf
        stsRampConf.setUser(servicRampConf.getUser());
        stsRampConf.setSigCryptoConfig(servicRampConf.getSigCryptoConfig());
        stsRampConf.setPwCbClass(servicRampConf.getPwCbClass());
        
        stsRampConf.setEncryptionUser(servicRampConf.getStsAlias());
        stsRampConf.setEncrCryptoConfig(servicRampConf.getStsCryptoConfig());
        
        policy.addAssertion(stsRampConf);
        
        return policy;
        
    }
    
    
    public static OMElement createRSTTempalteForSCT(int conversationVersion, 
            int wstVersion) throws RampartException {
        try {
            log.debug("Creating RSTTemplate for an SCT request");
            OMFactory fac = OMAbstractFactory.getOMFactory();
            
            OMNamespace wspNs = fac.createOMNamespace(SPConstants.P_NS, "wsp");
            OMElement rstTempl = fac.createOMElement(
                    SPConstants.REQUEST_SECURITY_TOKEN_TEMPLATE,
                    wspNs);
            
            //Create TokenType element and set the value
            OMElement tokenTypeElem = TrustUtil.createTokenTypeElement(
                    wstVersion, rstTempl);
            String tokenType = ConversationConstants
                    .getWSCNs(conversationVersion)
                    + ConversationConstants.TOKEN_TYPE_SECURITY_CONTEXT_TOKEN;
            tokenTypeElem.setText(tokenType);
            
            return rstTempl;
        } catch (TrustException e) {
            throw new RampartException("errorCreatingRSTTemplateForSCT", e);
        } catch (ConversationException e) {
            throw new RampartException("errorCreatingRSTTemplateForSCT", e);
        }
    }
    

    public static int getTimeToLive(RampartMessageData messageData) {

        RampartConfig rampartConfig = messageData.getPolicyData().getRampartConfig();
        if (rampartConfig != null) {
            String ttl = rampartConfig.getTimestampTTL();
            int ttl_i = 0;
            if (ttl != null) {
                try {
                    ttl_i = Integer.parseInt(ttl);
                } catch (NumberFormatException e) {
                    ttl_i = messageData.getTimeToLive();
                }
            }
            if (ttl_i <= 0) {
                ttl_i = messageData.getTimeToLive();
            }
            return ttl_i;
        } else {
            return RampartConfig.DEFAULT_TIMESTAMP_TTL;
        }
    }

    public static int getTimestampMaxSkew(RampartMessageData messageData) {

        RampartConfig rampartConfig = messageData.getPolicyData().getRampartConfig();
        if (rampartConfig != null) {
            String maxSkew = rampartConfig.getTimestampMaxSkew();
            int maxSkew_i = 0;
            if (maxSkew != null) {
                try {
                    maxSkew_i = Integer.parseInt(maxSkew);
                } catch (NumberFormatException e) {
                    maxSkew_i = messageData.getTimestampMaxSkew();
                }
            }
            if (maxSkew_i < 0) {
                maxSkew_i = 0;
            }
            return maxSkew_i;
        } else {
            return RampartConfig.DEFAULT_TIMESTAMP_MAX_SKEW;
        }
    }

    /**
     * Obtain a security context token.
     * @param rmd
     * @param secConvTok
     * @return Return the SecurityContextidentifier of the token
     * @throws TrustException
     * @throws RampartException
     */
    public static String getSecConvToken(RampartMessageData rmd,
            SecureConversationToken secConvTok) throws TrustException,
            RampartException {
        String action = TrustUtil.getActionValue(
                rmd.getWstVersion(),
                RahasConstants.RST_ACTION_SCT);
        
        // Get sts epr
        OMElement issuerEpr = secConvTok.getIssuerEpr();
        String issuerEprAddress = rmd.getMsgContext().getTo().getAddress();
        if(issuerEpr != null) {
            issuerEprAddress = RampartUtil.processIssuerAddress(issuerEpr);
        }
        
        //Find SC version
        int conversationVersion = rmd.getSecConvVersion();
        
        OMElement rstTemplate = RampartUtil.createRSTTempalteForSCT(
                conversationVersion, 
                rmd.getWstVersion());
        
        Policy stsPolicy = null;

        //Try boot strap policy
        Policy bsPol = secConvTok.getBootstrapPolicy();
        
        if(bsPol != null) {
            log.debug("BootstrapPolicy found");
            bsPol.addAssertion(rmd.getPolicyData().getRampartConfig());
            //copy the <wsoma:OptimizedMimeSerialization/> to BootstrapPolicy
            if (rmd.getPolicyData().getMTOMAssertion() != null) {
              bsPol.addAssertion(rmd.getPolicyData().getMTOMAssertion());  
            }
            stsPolicy = bsPol;
        } else {
            //No bootstrap policy use issuer policy
            log.debug("No bootstrap policy, using issuer policy");
            stsPolicy = rmd.getPolicyData().getIssuerPolicy();
        }
        
        String id = getToken(rmd, rstTemplate,
                issuerEprAddress, action, stsPolicy);

        if (log.isDebugEnabled()) {
            log.debug("SecureConversationToken obtained: id=" + id);
        }
        return id;
    }
    

    /**
     * Obtain an issued token.
     * @param rmd
     * @param issuedToken
     * @return The identifier of the issued token
     * @throws RampartException
     */
    public static String getIssuedToken(RampartMessageData rmd,
            IssuedToken issuedToken) throws RampartException {

        try {
            
            //TODO : Provide the overriding mechanism to provide a custom way of 
            //obtaining a token
            
            String action = TrustUtil.getActionValue(rmd.getWstVersion(),
                    RahasConstants.RST_ACTION_ISSUE);

            // Get sts epr
            String issuerEprAddress = RampartUtil.processIssuerAddress(issuedToken
                    .getIssuerEpr());

            OMElement rstTemplate = issuedToken.getRstTemplate();

            // Get STS policy
            Policy stsPolicy = (Policy)rmd.getMsgContext().getProperty(RampartMessageData.RAMPART_STS_POLICY);
            
            if( stsPolicy == null && issuedToken.getIssuerMex() != null) {
                stsPolicy = RampartUtil.getPolicyFromMetadataRef(issuedToken.getIssuerMex());
                RampartUtil.addRampartConfig(rmd, stsPolicy);
            }

            String id = getToken(rmd, rstTemplate, issuerEprAddress, action,
                    stsPolicy);

            if (log.isDebugEnabled()) {
                log.debug("Issued token obtained: id=" + id);
            }
            return id;
        } catch (TrustException e) {
            throw new RampartException("errorInObtainingToken", e);
        } 
    }
    
    /**
     * Request a token.
     * @param rmd
     * @param rstTemplate
     * @param issuerEpr
     * @param action
     * @param issuerPolicy
     * @return Return the identifier of the obtained token
     * @throws RampartException
     */
    public static String getToken(RampartMessageData rmd, OMElement rstTemplate,
            String issuerEpr, String action, Policy issuerPolicy) throws RampartException {

        try {
            //First check whether the user has provided the token
            MessageContext msgContext = rmd.getMsgContext();
            String customTokeId = (String) msgContext
                    .getProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN);
            if(customTokeId != null) {
                return customTokeId;
            } else {
    
                Axis2Util.useDOOM(false);
                
                STSClient client = new STSClient(rmd.getMsgContext()
                        .getConfigurationContext());
                // Set request action
                client.setAction(action);
                
                client.setVersion(rmd.getWstVersion());
                
                client.setRstTemplate(rstTemplate);
        
                // Set crypto information
                Crypto crypto = RampartUtil.getSignatureCrypto(rmd.getPolicyData().getRampartConfig(), 
                        rmd.getMsgContext().getAxisService().getClassLoader());
                CallbackHandler cbh = RampartUtil.getPasswordCB(rmd);
                client.setCryptoInfo(crypto, cbh);
        
                // Get service policy
                Policy servicePolicy = rmd.getServicePolicy();
        
                // Get service epr
                String servceEprAddress = rmd.getMsgContext()
                        .getOptions().getTo().getAddress();
        
                //If addressing version can be found set it
                Object addrVersionNs = msgContext.getProperty(AddressingConstants.WS_ADDRESSING_VERSION);
                if(addrVersionNs != null) {
                    client.setAddressingNs((String)addrVersionNs);
                }
                
                Options options = new Options();
                
                options.setUserName(rmd.getMsgContext().getOptions().getUserName());
                options.setPassword(rmd.getMsgContext().getOptions().getPassword());
                
                if (msgContext.getProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER) != null) {
                    Protocol protocolHandler =
                        (Protocol)msgContext.getProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER);;
                    options.setProperty(HTTPConstants.CUSTOM_PROTOCOL_HANDLER, protocolHandler);                 
                } 
                
                if (msgContext.getParameter(WSHandlerConstants.PW_CALLBACK_REF) != null ) {
                    Parameter pwCallback = msgContext.getParameter(WSHandlerConstants.PW_CALLBACK_REF);
                    client.addParameter(pwCallback);
                }
                
                client.setOptions(options);
                
                //Set soap version
                if (msgContext.isSOAP11()) {
                    client.setSoapVersion(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI);
                } else {
                    client.setSoapVersion(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI);
                }
                
                
                //Make the request
                org.apache.rahas.Token rst = 
                    client.requestSecurityToken(servicePolicy, 
                                                issuerEpr,
                                                issuerPolicy, 
                                                servceEprAddress);
                
                //Add the token to token storage
                rst.setState(Token.ISSUED);
                rmd.getTokenStorage().add(rst);
                Axis2Util.useDOOM(true);
                return rst.getId();
            }
        } catch (Exception e) {
            throw new RampartException("errorInObtainingToken", e);
        }
    }

    public static String getSoapBodyId(SOAPEnvelope env) {
        return addWsuIdToElement(env.getBody());
    }
    
    public static String addWsuIdToElement(OMElement elem) {
        String id;
        
        //first try to get the Id attr
        OMAttribute idAttr = elem.getAttribute(new QName("Id"));
        if(idAttr == null) {
            //then try the wsu:Id value
            idAttr = elem.getAttribute(new QName(WSConstants.WSU_NS, "Id"));
        }
        
        if(idAttr != null) {
            id = idAttr.getAttributeValue();
        } else {
            //Add an id
            OMNamespace ns = elem.getOMFactory().createOMNamespace(
                    WSConstants.WSU_NS, WSConstants.WSU_PREFIX);
            id = "Id-" + elem.hashCode();
            idAttr = elem.getOMFactory().createOMAttribute("Id", ns, id);
            elem.addAttribute(idAttr);
        }
        
        return id;
    }
    
    /**
     * Change the owner document of the given node. The method first attempts to move the node using
     * {@link Document#adoptNode(Node)}. If that fails, it will import the node into the target
     * document using {@link Document#importNode(Node, boolean)}.
     * 
     * @param targetDocument
     *            the target document
     * @param node
     *            the node to adopt or import
     * @return the adopted or imported node
     */
    public static Node adoptNode(Document targetDocument, Node node) {
        Node result = targetDocument.adoptNode(node);
        if (result == null) {
            result = targetDocument.importNode(node, true);
        }
        return result;
    }
    
    public static Element appendChildToSecHeader(RampartMessageData rmd,
            OMElement elem) {
        return appendChildToSecHeader(rmd, (Element)elem);
    }
    
    public static Element appendChildToSecHeader(RampartMessageData rmd,
            Element elem) {
        Element secHeaderElem = rmd.getSecHeader().getSecurityHeader();
        Node node = adoptNode(secHeaderElem.getOwnerDocument(), elem);
        return (Element)secHeaderElem.appendChild(node);
    }

    public static Element insertSiblingAfter(RampartMessageData rmd,
            Element child, Element sibling) {
        if (child == null) {
            return appendChildToSecHeader(rmd, sibling);
        } else {
            if (child.getOwnerDocument().equals(sibling.getOwnerDocument())) {

                if (child.getParentNode() == null
                        && !child.getLocalName().equals("UsernameToken")) {
                    rmd.getSecHeader().getSecurityHeader().appendChild(child);
                }
                ((OMElement) child).insertSiblingAfter((OMElement) sibling);
                return sibling;
            } else {
                Element newSib = (Element) child.getOwnerDocument().importNode(
                        sibling, true);
                ((OMElement) child).insertSiblingAfter((OMElement) newSib);
                return newSib;
            }
        }
    }
    
    public static Element insertSiblingBefore(RampartMessageData rmd, Element child, Element sibling) {
        if(child == null) {
            return appendChildToSecHeader(rmd, sibling);
        } else {
            if(child.getOwnerDocument().equals(sibling.getOwnerDocument())) {
                ((OMElement)child).insertSiblingBefore((OMElement)sibling);
                return sibling;
            } else {
                Element newSib = (Element)child.getOwnerDocument().importNode(sibling, true);
                ((OMElement)child).insertSiblingBefore((OMElement)newSib);
                return newSib;
            }
        }
        
    }
    
    public static List<WSEncryptionPart> getEncryptedParts(RampartMessageData rmd) {
		RampartPolicyData rpd = rmd.getPolicyData();
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
		List<WSEncryptionPart> encryptedPartsElements = getPartsAndElements(false, envelope,
				rpd.isEncryptBody() && !rpd.isEncryptBodyOptional(), rpd
						.getEncryptedParts(), rpd.getEncryptedElements(), rpd
						.getDeclaredNamespaces());
		return getContentEncryptedElements(encryptedPartsElements, envelope,
				rpd.getContentEncryptedElements(), rpd.getDeclaredNamespaces());
	}

	public static List<WSEncryptionPart> getSignedParts(RampartMessageData rmd) {
		RampartPolicyData rpd = rmd.getPolicyData();
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();

        //"signAllHeaders" indicates that all the headers should be signed.
        if (rpd.isSignAllHeaders()) {
            Iterator childHeaders = envelope.getHeader().getChildElements();
            while (childHeaders.hasNext()) {
               OMElement hb = (OMElement) childHeaders.next();
                if (!(hb.getLocalName().equals(WSConstants.WSSE_LN)
                        && hb.getNamespace().getNamespaceURI().equals(WSConstants.WSSE_NS))) {
                    rpd.addSignedPart(hb.getNamespace().getNamespaceURI(),hb.getLocalName());
                }
           }
        }

		return getPartsAndElements(true, envelope, rpd.isSignBody()
				&& !rpd.isSignBodyOptional(), rpd.getSignedParts(), rpd
				.getSignedElements(), rpd.getDeclaredNamespaces());
	}

	public static List<WSEncryptionPart> getSupportingEncryptedParts(RampartMessageData rmd,
			SupportingPolicyData rpd) {
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
		return getPartsAndElements(false, envelope, rpd.isEncryptBody()
				&& !rpd.isEncryptBodyOptional(), rpd.getEncryptedParts(), rpd
				.getEncryptedElements(), rpd.getDeclaredNamespaces());
	}

	public static List<WSEncryptionPart> getSupportingSignedParts(RampartMessageData rmd,
			SupportingPolicyData rpd) {
		SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
		return getPartsAndElements(true, envelope, rpd.isSignBody()
				&& !rpd.isSignBodyOptional(), rpd.getSignedParts(), rpd
				.getSignedElements(), rpd.getDeclaredNamespaces());
	}
    
    public static Set findAllPrefixNamespaces(OMElement currentElement, HashMap decNamespacess)
    {
    	Set<OMNamespace> results = new HashSet<OMNamespace>();
    	
    	//Find declared namespaces
    	findPrefixNamespaces(currentElement,results);
    	
    	//Get all default namespaces
    	List defaultNamespaces = getDefaultPrefixNamespaces(currentElement.getOMFactory());
        for (Object defaultNamespace : defaultNamespaces) {
            OMNamespace ns = (OMNamespace) defaultNamespace;
            results.add(ns);
        }

        for (Object o : decNamespacess.keySet()) {
            String prefix = (String) o;
            String ns = (String) decNamespacess.get(prefix);
            OMFactory omFactory = currentElement.getOMFactory();
            OMNamespace namespace = omFactory.createOMNamespace(ns, prefix);
            results.add(namespace);

        }
    	
    	return results;
    }

    private static void findPrefixNamespaces(OMElement e, Set<OMNamespace> results) {

        Iterator iterator = e.getAllDeclaredNamespaces();

        if (iterator != null) {
            while (iterator.hasNext())
                results.add((OMNamespace)iterator.next());
        }

        Iterator children = e.getChildElements();

        while (children.hasNext()) {
            findPrefixNamespaces((OMElement) children.next(), results);
        }
    }
    
    private static List getDefaultPrefixNamespaces(OMFactory factory)
    {
    	List<OMNamespace> namespaces = new ArrayList<OMNamespace>();

    	// put default namespaces here (sp, soapenv, wsu, etc...)
    	namespaces.add(factory.createOMNamespace(WSConstants.ENC_NS, WSConstants.ENC_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.SIG_NS, WSConstants.SIG_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.WSSE_NS, WSConstants.WSSE_PREFIX));
    	namespaces.add(factory.createOMNamespace(WSConstants.WSU_NS, WSConstants.WSU_PREFIX));
    	
    	return namespaces;
    	
    }
    
    public static List<WSEncryptionPart> getContentEncryptedElements (List<WSEncryptionPart> encryptedPartsElements,
                                                 SOAPEnvelope envelope,List<String> elements, HashMap decNamespaces ) {
        
        Set namespaces = findAllPrefixNamespaces(envelope, decNamespaces);

        for (String expression : elements) {
            try {
                XPath xp = new AXIOMXPath(expression);

                for (Object objectNamespace : namespaces) {
                    OMNamespace tmpNs = (OMNamespace) objectNamespace;
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                List selectedNodes = xp.selectNodes(envelope);

                for (Object selectedNode : selectedNodes) {
                    OMElement e = (OMElement) selectedNode;

                    String localName = e.getLocalName();
                    String namespace = e.getNamespace() != null ? e.getNamespace().getNamespaceURI() : null;

                    OMAttribute wsuIdAttribute = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                    String wsuId = null;
                    if (wsuIdAttribute != null) {
                        wsuId = wsuIdAttribute.getAttributeValue();
                    }

                    encryptedPartsElements.add(createEncryptionPart(localName,
                            wsuId, namespace, "Content", expression));

                }

            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RuntimeException(e);
            }
        }
        
     
        return encryptedPartsElements;
        
    }


    /**
     * Creates an Encryption or Signature paert with given name and id. Name must not be null.
     * @param name The name of the part
     * @param id The id of the part.
     * @return WSEncryptionPart.
     */
    public static WSEncryptionPart createEncryptionPart (String name, String id) {

        return createEncryptionPart(name, id, null, null, null);
    }

    /**
     * Creates an encryption part. Could be a part or could be an element pointed through xpath expression.
     * @param name Name of the element.
     * @param id The id of the element
     * @param namespace Namespace of the element.
     * @param modifier Modifier "Content" or "Element"
     * @return A WSEncryptionPart
     */
    public static WSEncryptionPart createEncryptionPart(String name, String id,
                                                         String namespace, String modifier) {

        return createEncryptionPart(name, id, namespace, modifier, null);
    }

     /**
     * Creates an encryption part. Could be a part or could be an element pointed through xpath expression.
     * @param name Name of the element.
     * @param id The id of the element
     * @param namespace Namespace of the element.
     * @param modifier Modifier "Content" or "Element"
     * @param xPath The xPath expression
      * @return A WSEncryptionPart
     */
    public static WSEncryptionPart createEncryptionPart(String name, String id,
                                                         String namespace, String modifier,String xPath) {

        // The part name must not be null !!
        assert name != null;

        WSEncryptionPart wsEncryptionPart = new WSEncryptionPart(name, namespace, modifier);
        wsEncryptionPart.setId(id);
        wsEncryptionPart.setXpath(xPath);

        return wsEncryptionPart;
    }
    
    public static List<WSEncryptionPart> getPartsAndElements(boolean sign, SOAPEnvelope envelope, boolean includeBody,
                                                             List<WSEncryptionPart> parts, List<String> elements,
                                                             HashMap decNamespaces) {

        List<OMElement> found = new ArrayList<OMElement>();
        List<WSEncryptionPart> result = new ArrayList<WSEncryptionPart>();

        // check body
        if(includeBody) {

            String wsuId = addWsuIdToElement(envelope.getBody());

            if( sign ) {
                result.add(createEncryptionPart(envelope.getBody().getLocalName(), wsuId,
                        null, null));
            } else {
                result.add(createEncryptionPart(envelope.getBody().getLocalName(), wsuId, null, "Content"));
            }

            // TODO can we remove this ?
            found.add( envelope.getBody() );
        }
        
        // Search envelope header for 'parts' from Policy (SignedParts/EncryptedParts)

        SOAPHeader header = envelope.getHeader();

        for (WSEncryptionPart part : parts) {
            if (part.getName() == null) {
                // NO name - search by namespace
                ArrayList headerList = header.getHeaderBlocksWithNSURI(part.getNamespace());

                for (Object aHeaderList : headerList) {
                    SOAPHeaderBlock shb = (SOAPHeaderBlock) aHeaderList;

                    // find reference in envelope
                    OMElement e = header.getFirstChildWithName(shb.getQName());

                    if (!found.contains(e)) {
                        // found new
                        found.add(e);

                        if (sign) {
                            result.add(createEncryptionPart(e.getLocalName(), null,
                                    part.getNamespace(), "Content"));
                        } else {

                            OMAttribute wsuIdAttribute = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                            String wsuId = null;
                            if (wsuIdAttribute != null) {
                                wsuId = wsuIdAttribute.getAttributeValue();
                            }

                            result.add(createEncryptionPart(e.getLocalName(),wsuId,
                                    part.getNamespace(), "Element"));
                        }
                    }
                }
            } else {
                // try to find
                OMElement e = header.getFirstChildWithName(new QName(part.getNamespace(), part.getName()));
                if (e != null) {
                    if (!found.contains(e)) {
                        // found new (reuse wsep)
                        found.add(e);
                        OMAttribute wsuId = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                        if (wsuId != null) {
                            part.setEncId(wsuId.getAttributeValue());
                        }

                        result.add(part);
                    }
                }
            }
        }
        
        // ?? Search for 'Elements' here
        
        // decide what exactly is going to be used - only the default namespaces, or the list of all declared namespaces in the message !
        Set namespaces = findAllPrefixNamespaces(envelope, decNamespaces);

        for (String expression : elements) {
            try {
                XPath xp = new AXIOMXPath(expression);

                for (Object objectNamespace : namespaces) {
                    OMNamespace tmpNs = (OMNamespace) objectNamespace;
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                List selectedNodes = xp.selectNodes(envelope);

                for (Object selectedNode : selectedNodes) {
                    OMElement e = (OMElement) selectedNode;
                    String localName = e.getLocalName();
                    String namespace = e.getNamespace() != null ? e.getNamespace().getNamespaceURI() : null;

                    if (sign) {

                        result.add(createEncryptionPart(localName, null, namespace, "Content", expression));

                    } else {

                        OMAttribute wsuIdAttribute = e.getAttribute(new QName(WSConstants.WSU_NS, "Id"));

                        String wsuId = null;
                        if (wsuIdAttribute != null) {
                            wsuId = wsuIdAttribute.getAttributeValue();
                        }

                        result.add(createEncryptionPart(localName, wsuId, namespace, "Element", expression));
                    }
                }

            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RuntimeException(e);
            }
        }

        return result;
    }
    
    /**
     * Get a element for SOAP 
     * @param envelope   SOAP Envelope of which we should check required elements
     * @param decNamespaces  Declared namespaces in RequiredElements assertion
     * @param expression  XPATH expression of required elements
     * @return
     */
    public static boolean checkRequiredElements(SOAPEnvelope envelope, HashMap decNamespaces, String expression) {

        // The XPath expression must be evaluated against the SOAP header
        // http://docs.oasis-open.org/ws-sx/ws-securitypolicy/200702/ws-securitypolicy-1.2-spec-os.html#_Toc161826519
        SOAPHeader header = envelope.getHeader();
        Set namespaces = findAllPrefixNamespaces(header, decNamespaces);

        try {
            XPath xp = new AXIOMXPath(expression);

            for (Object namespace : namespaces) {
                OMNamespace tmpNs = (OMNamespace) namespace;
                xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
            }

            List selectedNodes = xp.selectNodes(header);

            if (selectedNodes.size() == 0) {
                return false;
            }

        } catch (JaxenException e) {
            // This has to be changed to propagate an instance of a RampartException up
            throw new RuntimeException(e);
        }

        return true;
    }
    
    
    public static KeyGenerator getEncryptionKeyGenerator(String symEncrAlgo) throws WSSecurityException {
        KeyGenerator keyGen;
        try {
            /*
             * Assume AES as default, so initialize it
             */
            keyGen = KeyGenerator.getInstance("AES");
            if (symEncrAlgo.equalsIgnoreCase(WSConstants.TRIPLE_DES)) {
                keyGen = KeyGenerator.getInstance("DESede");
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_128)) {
                keyGen.init(128);
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_192)) {
                keyGen.init(192);
            } else if (symEncrAlgo.equalsIgnoreCase(WSConstants.AES_256)) {
                keyGen.init(256);
            } else {
                return null;
            }
        } catch (NoSuchAlgorithmException e) {
            throw new WSSecurityException(
                    WSSecurityException.UNSUPPORTED_ALGORITHM, null, null, e);
        }
        return keyGen;
    }
    
    /**
     * Creates the unique (reproducible) id for to hold the context identifier
     * of the message exchange.
     * @return Id to hold the context identifier in the message context
     */
    public static String getContextIdentifierKey(MessageContext msgContext) {
        return msgContext.getAxisService().getName();
    }
    
    
    /**
     * Returns the map of security context token identifiers
     * @return the map of security context token identifiers
     */
    public static Hashtable getContextMap(MessageContext msgContext) {
        //Fist check whether its there
        Object map = msgContext.getConfigurationContext().getProperty(
                ConversationConstants.KEY_CONTEXT_MAP);
        
        if(map == null) {
            //If not create a new one
            map = new Hashtable();
            //Set the map globally
            msgContext.getConfigurationContext().setProperty(
                    ConversationConstants.KEY_CONTEXT_MAP, map);
        }
        
        return (Hashtable)map;
    }
    
    public static boolean isTokenValid(RampartMessageData rmd, String id) throws RampartException {
        try {
            org.apache.rahas.Token token = rmd.getTokenStorage().getToken(id);
            return token!= null && token.getState() == org.apache.rahas.Token.ISSUED;
        } catch (TrustException e) {
            throw new RampartException("errorExtractingToken");
        } 
    }
    
    public static void setEncryptionUser(RampartMessageData rmd, WSSecEncryptedKey encrKeyBuilder)
            throws RampartException {
        RampartPolicyData rpd = rmd.getPolicyData();
        String encrUser = rpd.getRampartConfig().getEncryptionUser();
        setEncryptionUser(rmd, encrKeyBuilder, encrUser);
    }
    
    public static void setEncryptionUser(RampartMessageData rmd, WSSecEncryptedKey encrKeyBuilder,
            String encrUser) throws RampartException {
        RampartPolicyData rpd = rmd.getPolicyData();
        
        if (encrUser == null) {
            encrUser = rpd.getRampartConfig().getEncryptionUser();
        }
        
        if (encrUser == null || "".equals(encrUser)) {
            throw new RampartException("missingEncryptionUser");
        }
        if(encrUser.equals(WSHandlerConstants.USE_REQ_SIG_CERT)) {
            List<WSHandlerResult> resultsObj
                    = (List<WSHandlerResult>)rmd.getMsgContext().getProperty(WSHandlerConstants.RECV_RESULTS);
            if(resultsObj != null) {
                encrKeyBuilder.setUseThisCert(getReqSigCert(resultsObj));
                 
                //TODO This is a hack, this should not come under USE_REQ_SIG_CERT
                if(encrKeyBuilder.isCertSet()) {
                	encrKeyBuilder.setUserInfo(getUsername(resultsObj));
                }
                	
                
            } else {
                throw new RampartException("noSecurityResults");
            }
        } else {
            encrKeyBuilder.setUserInfo(encrUser);
        }
    }
    
    /**
     * Sets the keyIdentifierType of <code>WSSecSignature</code> or <code>WSSecEncryptedKey</code> 
     * according to the given <code>Token</code> and <code>RampartPolicyData</code>
     * First check the requirements specified under Token Assertion and if not found check 
     * the WSS11 and WSS10 assertions
     */
    
    public static void setKeyIdentifierType(RampartMessageData rmd, WSSecBase secBase,org.apache.ws.secpolicy.model.Token token) {

        // Use a reference rather than the binary security token if: the policy never allows the token to be
        // included; or this is the recipient and the token should only be included in requests; or this is
        // the initiator and the token should only be included in responses.
        final boolean useReference = token.getInclusion() == SPConstants.INCLUDE_TOKEN_NEVER
                                     || !rmd.isInitiator() && token.getInclusion() == SPConstants.INCLUDE_TOEKN_ALWAYS_TO_RECIPIENT
                                     || rmd.isInitiator() && token.getInclusion() == SPConstants.INCLUDE_TOEKN_ALWAYS_TO_INITIATOR;
        if (useReference) {

    		boolean tokenTypeSet = false;
    		
    		if(token instanceof X509Token) {
    			X509Token x509Token = (X509Token)token;
    			
    			if(x509Token.isRequireIssuerSerialReference()) {
    				secBase.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
    				tokenTypeSet = true;
    			} else if (x509Token.isRequireKeyIdentifierReference()) {
    				secBase.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
    				tokenTypeSet = true;
    			} else if (x509Token.isRequireThumbprintReference()) {
    				secBase.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
    				tokenTypeSet = true;
    			}
    		} 
    		
    		if (!tokenTypeSet) {
                final RampartPolicyData rpd = rmd.getPolicyData();
	    		Wss10 wss = rpd.getWss11();
				if (wss == null) {
					wss = rpd.getWss10();
				}
				
				if (wss.isMustSupportRefKeyIdentifier()) {
					secBase.setKeyIdentifierType(WSConstants.SKI_KEY_IDENTIFIER);
				} else if (wss.isMustSupportRefIssuerSerial()) {
					secBase.setKeyIdentifierType(WSConstants.ISSUER_SERIAL);
				} else if (wss instanceof Wss11
						&& ((Wss11) wss).isMustSupportRefThumbprint()) {
					secBase.setKeyIdentifierType(WSConstants.THUMBPRINT_IDENTIFIER);
				}
    		}
    		
		} else {
			secBase.setKeyIdentifierType(WSConstants.BST_DIRECT_REFERENCE);
		}
    }
    
    private static X509Certificate getReqSigCert(List<WSHandlerResult> results) {
        /*
        * Scan the results for a matching actor. Use results only if the
        * receiving Actor and the sending Actor match.
        */
        for (WSHandlerResult result : results) {

            List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                if (actInt == WSConstants.SIGN) {
                    return (X509Certificate) wsSecEngineResult.get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);
                }
            }
        }
        
        return null;
    }
    
    /**
     * Scan through <code>WSHandlerResult<code> list for a Username token and return
     * the username if a Username Token found 
     * @param results
     * @return
     */
    
    public static String getUsername(List<WSHandlerResult> results) {
        /*
         * Scan the results for a matching actor. Use results only if the
         * receiving Actor and the sending Actor match.
         */
        for (WSHandlerResult result : results) {

            List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();
            /*
            * Scan the results for a username token. Use the username
            * of this token to set the alias for the encryption user
            */
            for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                if (actInt == WSConstants.UT) {
                    WSUsernameTokenPrincipal principal = (WSUsernameTokenPrincipal) wsSecEngineResult.
                            get(WSSecurityEngineResult.TAG_PRINCIPAL);
                    return principal.getName();
                }
            }
        }
         
         return null;
    }

    public static String getRequestEncryptedKeyId(List<WSHandlerResult> results) {

        for (WSHandlerResult result : results) {

            List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                String encrKeyId = (String) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ID);
                if (actInt == WSConstants.ENCR &&
                        encrKeyId != null) {
                    if (encrKeyId.length() > 0) {
                        return encrKeyId;
                    }
                    else if (log.isDebugEnabled()) {
                        log.debug("Found encryption security processing result with empty id, skipping it: " + wsSecEngineResult);
                    }
                }
            }
        }

        return null;
    }
    
    public static byte[] getRequestEncryptedKeyValue(List<WSHandlerResult> results) {

        for (WSHandlerResult result : results) {

            List<WSSecurityEngineResult> wsSecEngineResults = result.getResults();
            /*
            * Scan the results for the first Signature action. Use the
            * certificate of this Signature to set the certificate for the
            * encryption action :-).
            */
            for (WSSecurityEngineResult wsSecEngineResult : wsSecEngineResults) {
                Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
                byte[] decryptedKey = (byte[]) wsSecEngineResult.get(WSSecurityEngineResult.TAG_SECRET);
                if (actInt == WSConstants.ENCR &&
                        decryptedKey != null) {
                    return decryptedKey;
                }
            }
        }
        
        return null;
    }
    
    /**
     * If the child is present insert the element as a sibling after him.
     * 
     * If the child is null, then prepend the element.
     * 
     * @param rmd
     * @param child
     * @param elem - element mentioned above
     * @return
     */
    public static Element insertSiblingAfterOrPrepend(RampartMessageData rmd, Element child, Element elem) {
        Element retElem = null;
        if (child != null) { // child is not null so insert sibling after
            retElem = RampartUtil.insertSiblingAfter(rmd, child, elem);
        } else { //Prepend
            retElem = prependSecHeader(rmd, elem);
        }

        return retElem;
    }

    public static Element insertSiblingBeforeOrPrepend(RampartMessageData rmd, Element child, Element elem) {
        Element retElem = null;
        if (child != null && child.getPreviousSibling() != null) {
            retElem = RampartUtil.insertSiblingBefore(rmd, child, elem);
        } else { //Prepend
            retElem = prependSecHeader(rmd, elem);
        }

        return retElem;
    }

    private static Element prependSecHeader(RampartMessageData rmd, Element elem) {
        Element retElem = null;

        Element secHeaderElem = rmd.getSecHeader().getSecurityHeader();
        Node node = secHeaderElem.getOwnerDocument().importNode(
                elem, true);
        Element firstElem = (Element) secHeaderElem.getFirstChild();

        if (firstElem == null) {
            retElem = (Element) secHeaderElem.appendChild(node);
        } else {
            if (firstElem.getOwnerDocument().equals(elem.getOwnerDocument())) {
                ((OMElement) firstElem).insertSiblingBefore((OMElement) elem);
                retElem = elem;
            } else {
                Element newSib = (Element) firstElem.getOwnerDocument().importNode(elem, true);
                ((OMElement) firstElem).insertSiblingBefore((OMElement) newSib);
                retElem = newSib;
            }
        }

        return retElem;
    }
    
    /**
     * Method to check whether security header is required in incoming message
     * @param rpd 
     * @return true if a security header is required in the incoming message
     */
    public static boolean isSecHeaderRequired(RampartPolicyData rpd, boolean initiator, 
                                                                                boolean inflow ) {
        
        // Checking for time stamp
        if ( rpd.isIncludeTimestamp() ) {
            return true;
        } 
        
        // Checking for signed parts and elements
        if (rpd.isSignBody() || rpd.getSignedParts().size() != 0 || 
                                    rpd.getSignedElements().size() != 0) {
            return true;
        }
        
        // Checking for encrypted parts and elements
        if (rpd.isEncryptBody() || rpd.getEncryptedParts().size() != 0 || 
                                    rpd.getEncryptedElements().size() != 0 ) {
            return true;
        }   
        
        // Checking for supporting tokens
        SupportingToken supportingTokens;
        
        if (!initiator && inflow || initiator && !inflow ) {
        
            List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
            for (SupportingToken supportingTok : supportingToks) {
                if (supportingTok != null && supportingTok.getTokens().size() != 0) {
                    return true;
                }
            }
            
            supportingTokens = rpd.getSignedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
            
            supportingTokens = rpd.getEndorsingSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
            
            supportingTokens = rpd.getSignedEndorsingSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
       
            supportingTokens = rpd.getEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
            
            supportingTokens = rpd.getSignedEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
            
            supportingTokens = rpd.getEndorsingEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
            
            supportingTokens = rpd.getSignedEndorsingEncryptedSupportingTokens();
            if (supportingTokens != null && supportingTokens.getTokens().size() != 0) {
                return true;
            }
        }
        
        return false;
        
    }

    public static void handleEncryptedSignedHeaders(List<WSEncryptionPart> encryptedParts,
                                                    List<WSEncryptionPart> signedParts, Document doc) {

        //TODO Is there a more efficient  way to do this ? better search algorithm 
        for (WSEncryptionPart signedPart : signedParts) {
            //This signed part is not a header
            if (signedPart.getNamespace() == null || signedPart.getName() == null) {
                continue;
            }

            for (WSEncryptionPart encryptedPart : encryptedParts) {

                if (encryptedPart.getNamespace() == null || encryptedPart.getName() == null) {
                    continue;
                }

                if (signedPart.getName().equals(encryptedPart.getName()) &&
                        signedPart.getNamespace().equals(encryptedPart.getNamespace())) {

                    String encDataID = encryptedPart.getEncId();

                    // TODO Do we need to go through the whole tree to find element by id ? Verify
                    Element encDataElem = WSSecurityUtil.findElementById(doc.getDocumentElement(), encDataID, false);

                    if (encDataElem != null) {
                        Element encHeader = (Element) encDataElem.getParentNode();
                        String encHeaderId = encHeader.getAttributeNS(WSConstants.WSU_NS, "Id");

                        //For some reason the id might not be available
                        // so the part/element with empty/null id won't be recognized afterwards. 
                        if (encHeaderId != null && !"".equals(encHeaderId.trim())) {
                            signedParts.remove(signedPart);

                            signedParts.add(createEncryptionPart(signedPart.getName(), encHeaderId,
                                    signedPart.getNamespace(),
                                    signedPart.getEncModifier(), signedPart.getXpath()));
                        }

                    }
                }
            }


        }

    }
    
    public static String getSigElementId(RampartMessageData rmd) {
        
        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        
        SOAPHeader header = envelope.getHeader();
        
        if (header == null ) {
            return null;
        }
        
        ArrayList secHeaders = header.getHeaderBlocksWithNSURI(WSConstants.WSSE_NS);
        
        if (secHeaders != null && secHeaders.size() > 0) {
            QName sigQName = new QName(Constants.SignatureSpecNS,Constants._TAG_SIGNATURE);
            QName wsuIdQName = new QName(WSConstants.WSU_NS,"Id");
            OMElement sigElem = ((SOAPHeaderBlock)secHeaders.get(0)).getFirstChildWithName(sigQName);
            OMAttribute wsuId = sigElem.getAttribute(wsuIdQName);
            
            if (wsuId != null) {
                return wsuId.getAttributeValue();
            }
            
            wsuId = sigElem.getAttribute(new QName("Id"));
            
            if (wsuId != null) {
                return wsuId.getAttributeValue();
            }
            
            
        }
        
        return null;
    }
    
    /**
     * We use this method to prevent the singleton behavior of WSSConfig
     * @return WSSConfig object with the latest settings.    
     */
    
    public static WSSConfig getWSSConfigInstance() {
        
        WSSConfig defaultWssConfig = WSSConfig.getNewInstance();
        WSSConfig wssConfig = WSSConfig.getNewInstance();
        
        wssConfig.setEnableSignatureConfirmation(defaultWssConfig.isEnableSignatureConfirmation());
        wssConfig.setTimeStampStrict(defaultWssConfig.isTimeStampStrict());
        wssConfig.setWsiBSPCompliant(defaultWssConfig.isWsiBSPCompliant());
        wssConfig.setPrecisionInMilliSeconds(defaultWssConfig.isPrecisionInMilliSeconds());
        
        return  wssConfig;
       
    }
    

    /**
     * Validate transport binding policy assertions.
     * In case an HttpsToken is required by the security policy the method will verify that the 
     * HTTPS transport was used indeed. Furthermore if the assertion requires a client certificate
     * being used, the method will try to obtain the client certificate chain first from the 
     * message context properties directly under the key {@link RampartConstants#HTTPS_CLIENT_CERT_KEY}
     * and, if the property is not available, will try to get the HttpsServletRequest from the 
     * message context properties (populated there by the AxisServlet if axis2 is running inside a servlet
     * engine) and retrieve the https client certificate chain from its attributes. The client certificate
     * chain is expected to be available under the <code>javax.servlet.request.X509Certificate</code>
     * attribute of the servlet request. No further trust verification is done for the client
     * certificate - the transport listener should have already verified this.
     * 
     * @param rmd
     * @throws RampartException
     */
    public static void validateTransport(RampartMessageData rmd) throws RampartException {

        MessageContext msgContext = rmd.getMsgContext();
        RampartPolicyData rpd = rmd.getPolicyData();
        AxisConfiguration axisConf = msgContext.getConfigurationContext().getAxisConfiguration();

        if (rpd == null) {
            return;
        }

        if (rpd.isTransportBinding() && !rmd.isInitiator()) {
            if (rpd.getTransportToken() instanceof HttpsToken) {
                try {
                    TransportInDescription transportIn = msgContext.getTransportIn();
                    if (transportIn == null) {
                        transportIn = msgContext.getOptions().getTransportIn();
                    }
                    
                    //maybe the transportIn was not populated by the receiver
                    if (transportIn == null) {
                        transportIn = axisConf.getTransportIn(msgContext.getIncomingTransportName());
                    }
                    
                    if (transportIn == null) {
                        throw new RampartException("httpsVerificationFailed");
                    }
                    
                    TransportListener receiver = transportIn.getReceiver();
                    String incomingEPR = receiver.getEPRsForService(msgContext.getAxisService().getName(),
                                                                          null)[0].getAddress();
                    if (incomingEPR == null) {
                        incomingEPR = msgContext.getIncomingTransportName();
                    }
    
                    if (!incomingEPR.startsWith(org.apache.axis2.Constants.TRANSPORT_HTTPS)) {
                        if (incomingEPR.indexOf(':') > 0) {
                            incomingEPR = incomingEPR.substring(0, incomingEPR.indexOf(':'));
                        }
                        throw new RampartException("invalidTransport", new String[] { incomingEPR });
                    }
                } catch (AxisFault af) {
                    String incomingTransport = msgContext.getIncomingTransportName();
                    if (!incomingTransport.equals(org.apache.axis2.Constants.TRANSPORT_HTTPS)) {
                        throw new RampartException("invalidTransport", new String[] { incomingTransport });
                    }
                }
                
                // verify client certificate used
                // try to obtain the client certificate chain directly from the message context
                // and then from the servlet request
                if (((HttpsToken) rpd.getTransportToken()).isRequireClientCertificate()) {
                    Object certificateChainProperty = msgContext.getProperty(RampartConstants.HTTPS_CLIENT_CERT_KEY);
                    if (certificateChainProperty instanceof X509Certificate[]) {
                        // HTTPS client certificate chain found
                        return;
                    } else {
                        Object requestProperty = msgContext.getProperty(HTTPConstants.MC_HTTP_SERVLETREQUEST);
                        if (requestProperty instanceof HttpServletRequest) {
                            HttpServletRequest request = (HttpServletRequest)requestProperty;
                            Object certificateChain = request.getAttribute("javax.servlet.request.X509Certificate"); //$NON-NLS-1$
                            if (certificateChain instanceof X509Certificate[]) {
                                // HTTPS client certificate chain found
                                return;
                            }
                        }
                    }
                    
                    // HTTPS client certificate chain NOT found
                    throw new RampartException("httpsClientCertValidationFailed");
                }

            }
        }
    }

    private static Crypto retrieveCryptoFromCache(String cryptoKey, String refreshInterval) {
        // cache hit
        if (cryptoStore.containsKey(cryptoKey)) {
            CachedCrypto cachedCrypto = cryptoStore.get(cryptoKey);
            if (refreshInterval != null) {
                if (cachedCrypto.creationTime + new Long(refreshInterval).longValue() > Calendar
                        .getInstance().getTimeInMillis()) {
                    log.debug("Cache Hit : Crypto Object was found in cache.");
                    return cachedCrypto.crypto;
                } else {
                    log.debug("Cache Miss : Crypto Object found in cache is expired.");
                    return null;
                }
            } else {
                log.debug("Cache Hit : Crypto Object was found in cache.");
                return cachedCrypto.crypto;
            }
        }
        // cache miss
        else {
            log.debug("Cache Miss : Crypto Object was not found in cache.");
            return null;
        }
    }

    private static void cacheCrypto(String cryptoKey, Crypto crypto) {
        cryptoStore.put(cryptoKey, new CachedCrypto(crypto, Calendar.getInstance()
                .getTimeInMillis()));
        log.debug("Crypto object is inserted into the Cache.");

    }

    /**
     * Returns SAML10 Assertion namespace. As follows,
     * http://docs.oasis-open.org/wss/oasis-wss-saml-token-profile-1.0#SAMLAssertionID
     * @return SAML10 assertion namespace.
     */
    public static String getSAML10AssertionNamespace() {

        StringBuilder stringBuilder = new StringBuilder(WSConstants.SAMLTOKEN_NS);
        stringBuilder.append("#").append(WSConstants.SAML_ASSERTION_ID);

        return stringBuilder.toString();

    }

    /**
     * Sets encryption crypto file or crypto reference key to signature crypto file or signature
     * crypto reference.
     * @param msgContext The message context to get signature crypto properties and encryption properties
     * will be set to same message context.
     */
    public static void setEncryptionCrypto(MessageContext msgContext) {
        setEncryptionCryptoFileProperty(msgContext);
        setEncryptionCryptoReferenceProperty(msgContext);
    }

    /**
     * Sets decryption crypto file or crypto reference key to signature crypto file or signature
     * crypto reference.
     * @param msgContext The message context to get signature crypto properties and decryption properties
     * will be set to same message context.
     */
    public static void setDecryptionCrypto(MessageContext msgContext) {
        setDecryptionCryptoFileProperty(msgContext);
        setDecryptionCryptoReferenceProperty(msgContext);
    }

    /**
     * Sets encryption crypto property reference id.- WSHandlerConstants.ENC_PROP_REF_ID
     * @param msgContext The message context.
     */
    private static void setEncryptionCryptoReferenceProperty (MessageContext msgContext) {
        setCryptoProperty(msgContext, WSHandlerConstants.SIG_PROP_REF_ID, WSHandlerConstants.ENC_PROP_REF_ID);
    }

    /**
     * Sets encryption crypto property file.- WSHandlerConstants.DEC_PROP_REF_ID
     * @param msgContext The message context.
     */
    private static void setDecryptionCryptoReferenceProperty (MessageContext msgContext) {
        setCryptoProperty(msgContext, WSHandlerConstants.SIG_PROP_REF_ID, WSHandlerConstants.DEC_PROP_REF_ID);
    }

    /**
     * Sets encryption crypto property file.- WSHandlerConstants.ENC_PROP_FILE
     * @param msgContext The message context.
     */
    private static void setEncryptionCryptoFileProperty (MessageContext msgContext) {
        setCryptoProperty(msgContext, WSHandlerConstants.SIG_PROP_FILE, WSHandlerConstants.ENC_PROP_FILE);
    }

    /**
     * Sets encryption crypto property file.- WSHandlerConstants.DEC_PROP_FILE
     * @param msgContext The message context.
     */
    private static void setDecryptionCryptoFileProperty (MessageContext msgContext) {
        setCryptoProperty(msgContext, WSHandlerConstants.SIG_PROP_FILE, WSHandlerConstants.DEC_PROP_FILE);
    }

    private static void setCryptoProperty(MessageContext msgContext, String signaturePropertyName,
                                          String cryptoPropertyName){

        /**
         * Encryption Crypto is loaded using WSHandlerConstants.ENC_PROP_FILE. If this is not
         * set in the message context set WSHandlerConstants.SIG_PROP_FILE as WSHandlerConstants.ENC_PROP_FILE.
         */
        if (msgContext.getProperty(cryptoPropertyName) == null) {


            String signaturePropertyFile = (String)msgContext.getProperty(signaturePropertyName);

            if (signaturePropertyFile == null) {

                if (log.isDebugEnabled()) {
                    log.debug("Signature crypto property file is not set. Property file key - "
                            + WSHandlerConstants.SIG_PROP_FILE);
                }
            } else {
                msgContext.setProperty(cryptoPropertyName, signaturePropertyFile);
            }
        }
    }

    /**
     * Returns true if needed to encrypt first.
     * @param rpd Rampart policy data
     * @return true if policy says we need to encrypt first else false.
     */
    public static boolean encryptFirst(RampartPolicyData rpd) {
        return SPConstants.ENCRYPT_BEFORE_SIGNING.equals(rpd.getProtectionOrder());
    }

    /**
     * Check if the given SOAP fault reports a security fault.
     * 
     * @param fault
     *            the SOAP fault; must not be <code>null</code>
     * @return <code>true</code> if the fault is a security fault; <code>false</code> otherwise
     */
    public static boolean isSecurityFault(SOAPFault fault) {
        String soapVersionURI = fault.getNamespaceURI();
        SOAPFaultCode code = fault.getCode();
        if (code == null) {
            // If no fault code is given, then it can't be security fault
            return false;
        } else if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
            return isSecurityFaultCode(code);
        } else {
            // For SOAP 1.2 security faults, the fault code is env:Sender, and the security fault code is
            // specified in the subcode
            SOAPFaultSubCode subCode = code.getSubCode();
            return subCode == null ? false : isSecurityFaultCode(subCode);
        }
    }
    
    private static boolean isSecurityFaultCode(SOAPFaultClassifier code) {
        QName value = code.getValueAsQName();
        return value == null ? false : value.getNamespaceURI().equals(WSConstants.WSSE_NS);
    }
    
    /**
     * @param rpd Rampart policy data instance. Must not be null.
     * @return A collection of all {@link UsernameToken} supporting token assertions in the specified Rampart policy instance. The method will check the following lists:
     * <ul>
     *     <li>{@link RampartPolicyData#getSupportingTokensList()}</li>
     *     <li>{@link RampartPolicyData#getSignedSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getSignedEndorsingSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getEndorsingSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getEncryptedSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getSignedEncryptedSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getEndorsingEncryptedSupportingTokens()}</li>
     *     <li>{@link RampartPolicyData#getSignedEndorsingEncryptedSupportingTokens()}</li>
     * </ul>
     */
    public static Collection<UsernameToken> getUsernameTokens(RampartPolicyData rpd) {
        Collection<UsernameToken> usernameTokens = new ArrayList<UsernameToken>();
        
        List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
        for (SupportingToken suppTok : supportingToks) {
            usernameTokens.addAll(getUsernameTokens(suppTok));
        }
        
        usernameTokens.addAll(getUsernameTokens(rpd.getSignedSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getSignedEndorsingSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getEndorsingSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getEncryptedSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getSignedEncryptedSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getEndorsingEncryptedSupportingTokens()));
        usernameTokens.addAll(getUsernameTokens(rpd.getSignedEndorsingEncryptedSupportingTokens()));

        return usernameTokens;
    }
    
    /**
     * @param suppTok The {@link SupportingToken} assertion to check for username tokens.
     * @return A collection of all tokens in the specified <code>suppTok</code> SupportingToken assertion which are instances of {@link UsernameToken}.
     * If the specified  <code>suppTok</code> SupportingToken assertion is <code>null</code>, an empty collection will be returned.
     */
    public static Collection<UsernameToken> getUsernameTokens(SupportingToken suppTok) {
        
        if (suppTok == null) {
            return new ArrayList<UsernameToken>();
        }
        
        Collection<UsernameToken> usernameTokens = new ArrayList<UsernameToken>();
        for (org.apache.ws.secpolicy.model.Token token : suppTok.getTokens()) {
            if (token instanceof UsernameToken) {
                usernameTokens.add((UsernameToken)token);
            }
        }
        
        return usernameTokens;
    }
}
