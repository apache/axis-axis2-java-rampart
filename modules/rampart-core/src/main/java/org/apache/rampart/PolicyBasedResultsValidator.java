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

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.om.xpath.AXIOMXPath;
import org.apache.axiom.om.OMNamespace;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.policy.RampartPolicyData;
import org.apache.rampart.policy.SupportingPolicyData;
import org.apache.rampart.util.RampartUtil;
import org.apache.ws.secpolicy.SPConstants;
import org.apache.ws.secpolicy.model.*;
import org.apache.ws.security.*;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoType;
import org.apache.ws.security.message.token.Timestamp;
import org.apache.ws.security.util.WSSecurityUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;
import org.w3c.dom.NodeList;
import org.jaxen.XPath;
import org.jaxen.JaxenException;

import javax.xml.namespace.QName;
import java.math.BigInteger;
import java.security.cert.X509Certificate;
import java.util.*;

public class PolicyBasedResultsValidator implements ExtendedPolicyValidatorCallbackHandler {
    
    private static Log log = LogFactory.getLog(PolicyBasedResultsValidator.class);

    public void validate(ValidatorData data, Vector results)
    throws RampartException {
        List<WSSecurityEngineResult> resultsList = new ArrayList<WSSecurityEngineResult>(results);
        this.validate(data, resultsList);
    }
    
    /** 
     * {@inheritDoc}
     */
    public void validate(ValidatorData data, List<WSSecurityEngineResult> results)
    throws RampartException {
        
        RampartMessageData rmd = data.getRampartMessageData();
        
        RampartPolicyData rpd = rmd.getPolicyData();
        
        //If there's Security policy present and no results 
        //then we should throw an error
        if(rpd != null && results == null) {
            throw new RampartException("noSecurityResults");
        }
        
        //Check presence of timestamp
        WSSecurityEngineResult tsResult = null;
        if(rpd != null &&  rpd.isIncludeTimestamp()) {
            tsResult = 
                WSSecurityUtil.fetchActionResult(results, WSConstants.TS);
            if(tsResult == null && !rpd.isIncludeTimestampOptional()) {
                throw new RampartException("timestampMissing");
            }
            
        }
        
        //sig/encr
        List<WSEncryptionPart> encryptedParts = RampartUtil.getEncryptedParts(rmd);
        if(rpd != null && rpd.isSignatureProtection() && isSignatureRequired(rmd)) {
            
            String sigId = RampartUtil.getSigElementId(rmd);

            encryptedParts.add(RampartUtil.createEncryptionPart(WSConstants.SIG_LN, sigId, WSConstants.SIG_NS,
                    RampartConstants.XML_ENCRYPTION_MODIFIER_ELEMENT));
        }
        
        List<WSEncryptionPart> signatureParts = RampartUtil.getSignedParts(rmd);

        //Timestamp is not included in sig parts
        if (rpd != null) {
            if (tsResult != null || !rpd.isIncludeTimestampOptional()) {
                if (rpd.isIncludeTimestamp()
                        && !rpd.isTransportBinding()) {
                    signatureParts.add(RampartUtil.createEncryptionPart(WSConstants.TIMESTAMP_TOKEN_LN, "timestamp"));
                }
            }
        }

        if(!rmd.isInitiator()) {
                        
            //Just an indicator for EndorsingSupportingToken signature
            SupportingToken endSupportingToken = null;
            if (rpd != null) {
                endSupportingToken = rpd.getEndorsingSupportingTokens();
            }

            if(endSupportingToken !=  null && !endSupportingToken.isOptional()) {
                SignedEncryptedParts endSignedParts = endSupportingToken.getSignedParts();
                if((endSignedParts != null && !endSignedParts.isOptional() &&
                        (endSignedParts.isBody() || 
                                endSignedParts.getHeaders().size() > 0)) ||
                                rpd.isIncludeTimestamp()) {

                    signatureParts.add(RampartUtil.createEncryptionPart("EndorsingSupportingTokens",
                            "EndorsingSupportingTokens"));
                }
            }
            //Just an indicator for SignedEndorsingSupportingToken signature
            SupportingToken sgndEndSupportingToken = null;
            if (rpd != null) {
                sgndEndSupportingToken = rpd.getSignedEndorsingSupportingTokens();
            }
            if(sgndEndSupportingToken != null && !sgndEndSupportingToken.isOptional()) {
                SignedEncryptedParts sgndEndSignedParts = sgndEndSupportingToken.getSignedParts();
                if((sgndEndSignedParts != null && !sgndEndSignedParts.isOptional() &&
                        (sgndEndSignedParts.isBody() || 
                                sgndEndSignedParts.getHeaders().size() > 0)) || 
                                rpd.isIncludeTimestamp()) {

                    signatureParts.add(RampartUtil.createEncryptionPart("SignedEndorsingSupportingTokens",
                            "SignedEndorsingSupportingTokens"));
                }
            }

            if (rpd != null) {
                List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
                for (SupportingToken supportingToken : supportingToks) {
                    if (supportingToken != null && !supportingToken.isOptional()) {
                        SupportingPolicyData policyData = new SupportingPolicyData();
                        policyData.build(supportingToken);
                        encryptedParts.addAll(RampartUtil.getSupportingEncryptedParts(rmd, policyData));
                        signatureParts.addAll(RampartUtil.getSupportingSignedParts(rmd, policyData));
                    }
                }
            }
        }
        
        validateEncrSig(data,encryptedParts, signatureParts, results);

        if(rpd != null && !rpd.isTransportBinding()) {
            validateProtectionOrder(data, results);
        }

        validateEncryptedParts(data, encryptedParts, results);

        validateSignedPartsHeaders(data, signatureParts, results);
        
        validateRequiredElements(data);

        //Supporting tokens
        if(!rmd.isInitiator()) {
            validateSupportingTokens(data, results);
        }
        
        /*
         * Now we can check the certificate used to sign the message. In the
         * following implementation the certificate is only trusted if either it
         * itself or the certificate of the issuer is installed in the keystore.
         * 
         * Note: the method verifyTrust(X509Certificate) allows custom
         * implementations with other validation algorithms for subclasses.
         */

        // Extract the signature action result from the action vector
        WSSecurityEngineResult actionResult = WSSecurityUtil.fetchActionResult(
                results, WSConstants.SIGN);

        if (actionResult != null) {
            X509Certificate returnCert = (X509Certificate) actionResult
                    .get(WSSecurityEngineResult.TAG_X509_CERTIFICATE);

            if (returnCert != null) {
                if (!verifyTrust(returnCert, rmd)) {
                    throw new RampartException ("trustVerificationError");
                }
            }
        }
        
        /*
         * Perform further checks on the timestamp that was transmitted in the
         * header. 
         * In the following implementation the timestamp is valid if :
         * Timestamp->Created < 'now' < Timestamp->Expires.
         * (Last test handled by WSS4J also if timeStampStrict enabled)
         *
         * Note: the method verifyTimestamp(Timestamp) allows custom
         * implementations with other validation algorithms for subclasses.
         */

        // Extract the timestamp action result from the action vector
        actionResult = WSSecurityUtil.fetchActionResult(results, WSConstants.TS);

        if (actionResult != null) {
            Timestamp timestamp = (Timestamp) actionResult
                    .get(WSSecurityEngineResult.TAG_TIMESTAMP);

            if (timestamp != null) {
                if (!verifyTimestamp(timestamp, rmd)) {
                    throw new RampartException("cannotValidateTimestamp");
                }
            }
        }
    }
    
    /**
     * @param encryptedParts
     * @param signatureParts
     */
    protected void validateEncrSig(ValidatorData data,List<WSEncryptionPart> encryptedParts,
                                   List<WSEncryptionPart> signatureParts, List<WSSecurityEngineResult> results)
    throws RampartException {
        List<Integer> actions = getSigEncrActions(results);
        boolean sig = false; 
        boolean encr = false;
        for (Object action : actions) {
            Integer act = (Integer) action;
            if (act == WSConstants.SIGN) {
                sig = true;
            } else if (act == WSConstants.ENCR) {
                encr = true;
            }
        }
        
        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();
        
        SupportingToken sgndSupTokens = rpd.getSignedSupportingTokens();
        SupportingToken sgndEndorSupTokens = rpd.getSignedEndorsingSupportingTokens();
        
        if(sig && signatureParts.size() == 0 
                && (sgndSupTokens == null || sgndSupTokens.getTokens().size() == 0)
                 && (sgndEndorSupTokens == null || sgndEndorSupTokens.getTokens().size() == 0)) {
            
            //Unexpected signature
            throw new RampartException("unexprectedSignature");
        } else if(!sig && signatureParts.size() > 0) {
            
            //required signature missing
            throw new RampartException("signatureMissing");
        }
        
        if(encr && encryptedParts.size() == 0) {
            
            //Check whether its just an encrypted key
            List<WSSecurityEngineResult> list = this.getResults(results, WSConstants.ENCR);

            boolean encrDataFound = false;
            for (WSSecurityEngineResult result : list) {
                ArrayList dataRefURIs = (ArrayList) result.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);
                if (dataRefURIs != null && dataRefURIs.size() != 0) {
                    encrDataFound = true;
                }
            }
            //TODO check whether the encrptedDataFound is an UsernameToken
            if(encrDataFound && !isUsernameTokenPresent(data)) {
                //Unexpected encryption
                throw new RampartException("unexprectedEncryptedPart");
            }
        } else if(!encr && encryptedParts.size() > 0) {
            
            //required signature missing
            throw new RampartException("encryptionMissing");
        }
    }

    /**
     * @param data
     * @param results
     */
    protected void validateSupportingTokens(ValidatorData data, List<WSSecurityEngineResult> results)
    throws RampartException {
        
        //Check for UsernameToken
        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();
        List<SupportingToken> supportingTokens = rpd.getSupportingTokensList();
        for (SupportingToken suppTok : supportingTokens) {
            handleSupportingTokens(results, suppTok);
        }
        SupportingToken signedSuppToken = rpd.getSignedSupportingTokens();
        handleSupportingTokens(results, signedSuppToken);
        SupportingToken signedEndSuppToken = rpd.getSignedEndorsingSupportingTokens();
        handleSupportingTokens(results, signedEndSuppToken);
        SupportingToken endSuppToken = rpd.getEndorsingSupportingTokens();
        handleSupportingTokens(results, endSuppToken);
    }

    /**
     * @param results
     * @param suppTok
     * @throws RampartException
     */
    protected void handleSupportingTokens(List<WSSecurityEngineResult> results, SupportingToken suppTok) throws RampartException {
        
        if(suppTok == null) {
            return;
        }
        
        ArrayList tokens = suppTok.getTokens();
        for (Object objectToken : tokens) {
            Token token = (Token) objectToken;
            if (token instanceof UsernameToken) {
                UsernameToken ut = (UsernameToken) token;
                //Check presence of a UsernameToken
                WSSecurityEngineResult utResult = WSSecurityUtil.fetchActionResult(results, WSConstants.UT);
                
                if (utResult == null && !ut.isOptional()) {
                    throw new RampartException("usernameTokenMissing");
                }
                
                org.apache.ws.security.message.token.UsernameToken wssUt = 
                		(org.apache.ws.security.message.token.UsernameToken) utResult.get(WSSecurityEngineResult.TAG_USERNAME_TOKEN);
                
                if(ut.isNoPassword() && wssUt.getPassword() != null) {
                	throw new RampartException("invalidUsernameTokenType");
                }
                
            	if(ut.isHashPassword() && !wssUt.isHashed()) {
                	throw new RampartException("invalidUsernameTokenType");
                } else if (!ut.isHashPassword() && (wssUt.getPassword() == null ||
                        !wssUt.getPasswordType().equals(WSConstants.PASSWORD_TEXT))) {
                	throw new RampartException("invalidUsernameTokenType");
                }
                
                

            } else if (token instanceof IssuedToken) {
                //TODO is is enough to check for ST_UNSIGNED results ??
                WSSecurityEngineResult samlResult = WSSecurityUtil.fetchActionResult(results, WSConstants.ST_UNSIGNED);
                if (samlResult == null) {
                    throw new RampartException("samlTokenMissing");
                }
            } else if (token instanceof X509Token) {
                X509Token x509Token = (X509Token) token;
                WSSecurityEngineResult x509Result = WSSecurityUtil.fetchActionResult(results, WSConstants.BST);
                if (x509Result == null && !x509Token.isOptional()) {
                    throw new RampartException("binaryTokenMissing");
                }
            }
        }
    }
    
    
    

    /**
     * @param data
     * @param results
     */
    protected void validateProtectionOrder(ValidatorData data, List<WSSecurityEngineResult> results)
    throws RampartException {
        
        String protectionOrder = data.getRampartMessageData().getPolicyData().getProtectionOrder();
        List<Integer> sigEncrActions = this.getSigEncrActions(results);
        
        if(sigEncrActions.size() < 2) {
            //There are no results to COMPARE
            return;
        }
        
        boolean sigNotPresent = true; 
        boolean encrNotPresent = true;

        for (Object sigEncrAction : sigEncrActions) {
            Integer act = (Integer) sigEncrAction;
            if (act == WSConstants.SIGN) {
                sigNotPresent = false;
            } else if (act == WSConstants.ENCR) {
                encrNotPresent = false;
            }
        }
        
        // Only one action is present, so there is no order to check
        if ( sigNotPresent || encrNotPresent ) {
            return;
        }
        
        
        boolean done = false;
        if(SPConstants.SIGN_BEFORE_ENCRYPTING.equals(protectionOrder)) {
                        
            boolean sigFound = false;
            for (Iterator iter = sigEncrActions.iterator(); 
                iter.hasNext() || !done;) {
                Integer act = (Integer) iter.next();
                if(act == WSConstants.ENCR && ! sigFound ) {
                    // We found ENCR and SIGN has not been found - break and fail
                    break;
                }
                if(act == WSConstants.SIGN) {
                    sigFound = true;
                } else if(sigFound) {
                    //We have an ENCR action after sig
                    done = true;
                }
            }
            
        } else {
            boolean encrFound = false;
            for (Object sigEncrAction : sigEncrActions) {
                Integer act = (Integer) sigEncrAction;
                if (act == WSConstants.SIGN && !encrFound) {
                    // We found SIGN and ENCR has not been found - break and fail
                    break;
                }
                if (act == WSConstants.ENCR) {
                    encrFound = true;
                } else if (encrFound) {
                    //We have an ENCR action after sig
                    done = true;
                }
            }
        }
        
        if(!done) {
            throw new RampartException("protectionOrderMismatch");
        }
    }


    protected List<Integer> getSigEncrActions(List<WSSecurityEngineResult> results) {
        List<Integer> sigEncrActions = new ArrayList<Integer>();
        for (WSSecurityEngineResult result : results) {
            Integer action = (Integer) (result)
                    .get(WSSecurityEngineResult.TAG_ACTION);

            if (WSConstants.SIGN == action || WSConstants.ENCR == action) {
                sigEncrActions.add(action);
            }

        }
        return sigEncrActions;
    }

    protected void validateEncryptedParts(ValidatorData data,
                                          List<WSEncryptionPart> encryptedParts, List<WSSecurityEngineResult> results)
                                                                                throws RampartException {
        
        RampartMessageData rmd = data.getRampartMessageData();
        
        ArrayList encrRefs = getEncryptedReferences(results);
        
        RampartPolicyData rpd = rmd.getPolicyData();

        // build the list of encrypted nodes based on the dataRefs xpath expressions
        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();
        Set namespaces = RampartUtil.findAllPrefixNamespaces(envelope,
                                                             rpd.getDeclaredNamespaces());

        Map decryptedElements = new HashMap();
        for (Object encrRef : encrRefs) {
            WSDataRef dataRef = (WSDataRef) encrRef;

            if (dataRef == null || dataRef.getXpath() == null) {
                continue;
            }

            try {
                XPath xp = new AXIOMXPath(dataRef.getXpath());

                for (Object namespaceObject : namespaces) {
                    OMNamespace tmpNs = (OMNamespace) namespaceObject;
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                for (Object o : xp.selectNodes(envelope)) {
                    decryptedElements.put(o, dataRef.isContent());
                }


            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RampartException("An error occurred while searching for decrypted elements.", e);
            }

        }

        //Check for encrypted body
        if(rpd.isEncryptBody()&& !rpd.isEncryptBodyOptional()) {
            
            if( !isRefIdPresent(encrRefs, data.getBodyEncrDataId())){
                throw new RampartException("encryptedPartMissing", 
                        new String[]{data.getBodyEncrDataId()});
            }
        }

        for (WSEncryptionPart encryptedPart : encryptedParts) {

            //This is the encrypted Body and we already checked encrypted body
            if (encryptedPart.getName().equals(WSConstants.ELEM_BODY)) {
                continue;
            }

            if ((WSConstants.SIG_LN.equals(encryptedPart.getName()) &&
                    WSConstants.SIG_NS.equals(encryptedPart.getNamespace()))
                    || encryptedPart.getEncModifier().equals(WSConstants.ELEM_HEADER)) {
                if (!isRefIdPresent(encrRefs, new QName(encryptedPart.getNamespace(), encryptedPart.getName()))) {
                    throw new RampartException("encryptedPartMissing",
                            new String[]{encryptedPart.getNamespace() + ":" + encryptedPart.getName()});
                }
                continue;
            }

            // it is not a header or body part... verify encrypted xpath elements
            String xpath = encryptedPart.getXpath();
            boolean found = false;
            try {
                XPath xp = new AXIOMXPath(xpath);

                for (Object namespaceObject : namespaces) {
                    OMNamespace tmpNs = (OMNamespace) namespaceObject;
                    xp.addNamespace(tmpNs.getPrefix(), tmpNs.getNamespaceURI());
                }

                for (Object o : xp.selectNodes(envelope)) {
                    Object result = decryptedElements.get(o);
                    if (result != null &&
                            ("Element".equals(encryptedPart.getEncModifier())
                                    ^ (Boolean) result)) {
                        found = true;
                        break;
                    }
                }

                if (!found) {
                    throw new RampartException("encryptedPartMissing",
                            new String[]{xpath});
                }


            } catch (JaxenException e) {
                // This has to be changed to propagate an instance of a RampartException up
                throw new RampartException("An error occurred while searching for decrypted elements.", e);
            }

        }
        
    }
    
    public void validateRequiredElements(ValidatorData data) throws RampartException {
        
        RampartMessageData rmd = data.getRampartMessageData();
        
        RampartPolicyData rpd = rmd.getPolicyData();
        
        SOAPEnvelope envelope = rmd.getMsgContext().getEnvelope();

        for (String expression : rpd.getRequiredElements()) {

            if (!RampartUtil.checkRequiredElements(envelope, rpd.getDeclaredNamespaces(), expression)) {
                throw new RampartException("requiredElementsMissing", new String[]{expression});
            }
        }
        
    }

    protected void validateSignedPartsHeaders(ValidatorData data, List<WSEncryptionPart> signatureParts,
                                              List<WSSecurityEngineResult> results)
    throws RampartException {
        
        RampartMessageData rmd = data.getRampartMessageData();
        
        Node envelope = rmd.getDocument().getFirstChild();
        
        WSSecurityEngineResult[] actionResults = fetchActionResults(results, WSConstants.SIGN);

        // Find elements that are signed
        List<QName> actuallySigned = new ArrayList<QName>();
        if (actionResults != null) {
            for (WSSecurityEngineResult actionResult : actionResults) {

                List wsDataRefs = (List) actionResult.get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

                // if header was encrypted before it was signed, protected
                // element is 'EncryptedHeader.' the actual element is
                // first child element

                for (Object objectDataReference : wsDataRefs) {
                    WSDataRef wsDataRef = (WSDataRef) objectDataReference;
                    Element protectedElement = wsDataRef.getProtectedElement();
                    if (protectedElement.getLocalName().equals("EncryptedHeader")) {
                        NodeList nodeList = protectedElement.getChildNodes();
                        for (int x = 0; x < nodeList.getLength(); x++) {
                            if (nodeList.item(x).getNodeType() == Node.ELEMENT_NODE) {
                                String ns = (nodeList.item(x)).getNamespaceURI();
                                String ln = (nodeList.item(x)).getLocalName();
                                actuallySigned.add(new QName(ns, ln));
                                break;
                            }
                        }
                    } else {
                        String ns = protectedElement.getNamespaceURI();
                        String ln = protectedElement.getLocalName();
                        actuallySigned.add(new QName(ns, ln));
                    }
                }

            }
        }

        for (WSEncryptionPart wsep : signatureParts) {
            if (wsep.getName().equals(WSConstants.ELEM_BODY)) {

                QName bodyQName;

                if (WSConstants.URI_SOAP11_ENV.equals(envelope.getNamespaceURI())) {
                    bodyQName = new SOAP11Constants().getBodyQName();
                } else {
                    bodyQName = new SOAP12Constants().getBodyQName();
                }

                if (!actuallySigned.contains(bodyQName) && !rmd.getPolicyData().isSignBodyOptional()) {
                    // soap body is not signed
                    throw new RampartException("bodyNotSigned");
                }

            } else if (wsep.getName().equals(WSConstants.ELEM_HEADER) ||
                    wsep.getXpath() != null) {
                // TODO earlier this was wsep.getType() == WSConstants.PART_TYPE_ELEMENT
                // This means that encrypted element of an XPath expression type. Therefore we are checking
                // now whether an XPath expression exists. - Verify

                Element element = WSSecurityUtil.findElement(
                        envelope, wsep.getName(), wsep.getNamespace());

                if (element == null) {
                    // The signedpart header or element we are checking is not present in 
                    // soap envelope - this is allowed
                    continue;
                }

                // header or the element present in soap envelope - verify that it is part of signature
                if (actuallySigned.contains(new QName(element.getNamespaceURI(), element.getLocalName()))) {
                    continue;
                }

                String msg = wsep.getXpath() != null ?
                        "signedPartHeaderNotSigned" : "signedElementNotSigned";

                // header or the element defined in policy is present but not signed
                throw new RampartException(msg, new String[]{wsep.getNamespace() + ":" + wsep.getName()});

            }
        }
    }

    
    protected boolean isSignatureRequired(RampartMessageData rmd) {
        RampartPolicyData rpd = rmd.getPolicyData();
        return (rpd.isSymmetricBinding() && rpd.getSignatureToken() != null) ||
                (!rpd.isSymmetricBinding() && !rpd.isTransportBinding() && 
                        ((rpd.getInitiatorToken() != null && rmd.isInitiator())
                                || rpd.getRecipientToken() != null && !rmd.isInitiator()));
    }


    /*
    * Verify whether timestamp of the message is valid.
    * If timeStampStrict is enabled in rampartConfig; testing of timestamp has not expired
    * ('now' is before ts->Expires) is also handled earlier by WSS4J without timeskew.
    * TODO must write unit tests
    */
    protected boolean verifyTimestamp(Timestamp timestamp, RampartMessageData rmd) throws RampartException {

        long maxSkew = RampartUtil.getTimestampMaxSkew(rmd);

        //Verify that ts->Created is before 'now'
        Date createdTime = timestamp.getCreated();
        if (createdTime != null) {
            long now = Calendar.getInstance().getTimeInMillis();

            //calculate the tolerance limit for timeskew of the 'Created' in timestamp
            if (maxSkew > 0) {
                now += (maxSkew * 1000);
            }

            // fail if ts->Created is after 'now'
            if (createdTime.getTime() > now) {
                return false;
            }
        }

        //Verify that ts->Expires is after now.
        Date expires = timestamp.getExpires();

        if (expires != null) {
            long now = Calendar.getInstance().getTimeInMillis();
            //calculate the tolerance limit for timeskew of the 'Expires' in timestamp
            if (maxSkew > 0) {
                now -= (maxSkew * 1000);
            }
            //fail if ts->Expires is before 'now'
            if (expires.getTime() < now) {
                return false;
            }
        }

        return true;
    }
    
    /**
     * Evaluate whether a given certificate should be trusted.
     * Hook to allow subclasses to implement custom validation methods however they see fit.
     * <p/>
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer might be fooled by a phony DN (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @param rmd To get signature keystore information.
     * @return true if the certificate is trusted, false if not (AxisFault is thrown for exceptions during CertPathValidation)
     * @throws RampartException If an error occurred during validation.
     */
    protected boolean verifyTrust(X509Certificate cert, RampartMessageData rmd) throws RampartException {

        // If no certificate was transmitted, do not trust the signature
        if (cert == null) {
            return false;
        }

        Crypto crypto = RampartUtil.getSignatureCrypto(
                    rmd.getPolicyData().getRampartConfig(),
                    rmd.getCustomClassLoader());


        // TODO removing this with WSS4J 1.6 migration. We do not have a way to get alias
        // Therefore cannot set alias to message context. What will be affected from this ?
        // rmd.getMsgContext().setProperty(RampartMessageData.SIGNATURE_CERT_ALIAS, alias);

        // TODO this validation we are doing in SignatureProcessor.handleToken (WSS4J) So why we need to do again ?
        // investigate

        return isCertificateTrusted(cert, crypto);

    }


    /**
     * TODO - This is directly copied from WSS4J (SignatureTrustValidator).
     * We need to use to Validators instead of following code. REFACTOR later.
     *
     * Evaluate whether a given certificate should be trusted.
     *
     * Policy used in this implementation:
     * 1. Search the keystore for the transmitted certificate
     * 2. Search the keystore for a connection to the transmitted certificate
     * (that is, search for certificate(s) of the issuer of the transmitted certificate
     * 3. Verify the trust path for those certificates found because the search for the issuer
     * might be fooled by a phony DN (String!)
     *
     * @param cert the certificate that should be validated against the keystore
     * @param crypto A crypto instance to use for trust validation
     * @return true if the certificate is trusted, false if not
     * @throws RampartException  If an error occurred during validation.
     */
    protected boolean isCertificateTrusted(
        X509Certificate cert,
        Crypto crypto
    ) throws RampartException {
        String subjectString = cert.getSubjectX500Principal().getName();
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        if (log.isDebugEnabled()) {
            log.debug("Transmitted certificate has subject " + subjectString);
            log.debug(
                "Transmitted certificate has issuer " + issuerString + " (serial "
                + issuerSerial + ")"
            );
        }

        //
        // FIRST step - Search the keystore for the transmitted certificate
        //
        if (isCertificateInKeyStore(crypto, cert)) {
            return true;
        }

        //
        // SECOND step - Search for the issuer cert (chain) of the transmitted certificate in the
        // keystore or the truststore
        //
        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.SUBJECT_DN);
        cryptoType.setSubjectDN(issuerString);
        X509Certificate[] foundCerts = new X509Certificate[0];
        try {
            foundCerts = crypto.getX509Certificates(cryptoType);
        } catch (WSSecurityException e) {
            throw new RampartException("noCertForSubject", e);
        }

        // If the certs have not been found, the issuer is not in the keystore/truststore
        // As a direct result, do not trust the transmitted certificate
        if (foundCerts == null || foundCerts.length < 1) {
            if (log.isDebugEnabled()) {
                log.debug(
                    "No certs found in keystore for issuer " + issuerString
                    + " of certificate for " + subjectString
                );
            }
            return false;
        }

        //
        // THIRD step
        // Check the certificate trust path for the issuer cert chain
        //
        if (log.isDebugEnabled()) {
            log.debug(
                "Preparing to validate certificate path for issuer " + issuerString
            );
        }
        //
        // Form a certificate chain from the transmitted certificate
        // and the certificate(s) of the issuer from the keystore/truststore
        //
        X509Certificate[] x509certs = new X509Certificate[foundCerts.length + 1];
        x509certs[0] = cert;
        for (int j = 0; j < foundCerts.length; j++) {
            x509certs[j + 1] = (X509Certificate)foundCerts[j];
        }

        //
        // Use the validation method from the crypto to check whether the subjects'
        // certificate was really signed by the issuer stated in the certificate
        //
        // TODO we need to configure enable revocation ...
        try {
            if (crypto.verifyTrust(x509certs, false)) {
                if (log.isDebugEnabled()) {
                    log.debug(
                        "Certificate path has been verified for certificate with subject "
                         + subjectString
                    );
                }
                return true;
            }
        } catch (WSSecurityException e) {
            throw new RampartException("certPathVerificationFailed", e);
        }

        if (log.isDebugEnabled()) {
            log.debug(
                "Certificate path could not be verified for certificate with subject "
                + subjectString
            );
        }
        return false;
    }

    /**
     * Check to see if the certificate argument is in the keystore
     * TODO Directly copied from WSS4J (SignatureTrustValidator) - Optimize later
     * @param crypto A Crypto instance to use for trust validation
     * @param cert The certificate to check
     * @return true if cert is in the keystore
     * @throws RampartException If certificates are not found for given issuer and serial number.
     */
    protected boolean isCertificateInKeyStore(
        Crypto crypto,
        X509Certificate cert
    ) throws RampartException {
        String issuerString = cert.getIssuerX500Principal().getName();
        BigInteger issuerSerial = cert.getSerialNumber();

        CryptoType cryptoType = new CryptoType(CryptoType.TYPE.ISSUER_SERIAL);
        cryptoType.setIssuerSerial(issuerString, issuerSerial);
        X509Certificate[] foundCerts = new X509Certificate[0];
        try {
            foundCerts = crypto.getX509Certificates(cryptoType);
        } catch (WSSecurityException e) {
            throw new RampartException("noCertificatesForIssuer", new String[]{issuerString,
                    issuerSerial.toString()}, e);
        }

        //
        // If a certificate has been found, the certificates must be compared
        // to ensure against phony DNs (compare encoded form including signature)
        //
        if (foundCerts != null && foundCerts[0] != null && foundCerts[0].equals(cert)) {
            if (log.isDebugEnabled()) {
                log.debug(
                        "Direct trust for certificate with " + cert.getSubjectX500Principal().getName()
                );
            }
            return true;
        }
        if (log.isDebugEnabled()) {
            log.debug(
                    "No certificate found for subject from issuer with " + issuerString
                            + " (serial " + issuerSerial + ")"
            );
        }
        return false;
    }

    
    protected ArrayList getEncryptedReferences(List<WSSecurityEngineResult> results) {
        
        //there can be multiple ref lists
        List<WSSecurityEngineResult> encrResults = getResults(results, WSConstants.ENCR);
        
        ArrayList refs = new ArrayList();

        for (WSSecurityEngineResult engineResult : encrResults) {
            ArrayList dataRefUris = (ArrayList) engineResult
                    .get(WSSecurityEngineResult.TAG_DATA_REF_URIS);

            //take only the ref list processing results
            if (dataRefUris != null) {
                for (Iterator iterator = dataRefUris.iterator(); iterator
                        .hasNext(); ) {
                    WSDataRef uri = (WSDataRef) iterator.next();
                    refs.add(uri);
                }
            }
        }
        
        return refs;
    }
    
    
    
    protected List<WSSecurityEngineResult> getResults(List<WSSecurityEngineResult> results, int action) {
        
        List<WSSecurityEngineResult> list = new ArrayList<WSSecurityEngineResult>();

        for (WSSecurityEngineResult result : results) {
            // Check the result of every action whether it matches the given
            // action
            Integer actInt = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (actInt == action) {
                list.add(result);
            }
        }
        
        return list;
    }
    
    protected boolean isUsernameTokenPresent(ValidatorData data) {
        
        //TODO This can be integrated with supporting token processing
        // which also checks whether Username Tokens present
        
        RampartPolicyData rpd = data.getRampartMessageData().getPolicyData();
        
        List<SupportingToken> supportingToks = rpd.getSupportingTokensList();
        for (SupportingToken suppTok : supportingToks) {
            if (isUsernameTokenPresent(suppTok)) {
                return true;
            }
        }
        
        SupportingToken signedSuppToken = rpd.getSignedSupportingTokens();
        if(isUsernameTokenPresent(signedSuppToken)) {
            return true;
        }
        
        SupportingToken signedEndSuppToken = rpd.getSignedEndorsingSupportingTokens();
        if(isUsernameTokenPresent(signedEndSuppToken)) {
            return true;
        }
        
        SupportingToken endSuppToken = rpd.getEndorsingSupportingTokens();
        return isUsernameTokenPresent(endSuppToken);


    }
    
    protected boolean isUsernameTokenPresent(SupportingToken suppTok) {
        
        if(suppTok == null) {
            return false;
        }
        
        ArrayList tokens = suppTok.getTokens();
        for (Iterator iter = tokens.iterator(); iter.hasNext();) {
            Token token = (Token) iter.next();
            if(token instanceof UsernameToken) {
                return true;
            }
        }
        
        return false;
    }
    
    private boolean isRefIdPresent(ArrayList refList , String id) {

        if(id != null && id.charAt(0) == '#') {
           id = id.substring(1);
        }

        for (Object aRefList : refList) {
            WSDataRef dataRef = (WSDataRef) aRefList;

            //ArrayList can contain null elements
            if (dataRef == null) {
                continue;
            }
            //Try to get the wsuId of the decrypted element
            String dataRefUri = dataRef.getWsuId();
            //If not found, try the reference Id of encrypted element ( we set the same Id when we
            // decrypted element in WSS4J)  
            // TODO wsu id must present. We need to find the scenario where it is not set
            // if (dataRefUri == null) {
            //    dataRefUri = dataRef.getProtectedElement().getAttribute("Id"); // TODO check whether this is correct
                // earlier it was dataRefUri = dataRef.getDataref();
            //}
            if (dataRefUri != null && dataRefUri.equals(id)) {
                return true;
            }
        }
        
        return false;
        
    }
    
    public static WSSecurityEngineResult[] fetchActionResults(List<WSSecurityEngineResult> wsSecurityEngineResults, int action) {
        List<WSSecurityEngineResult> wsResult = new ArrayList<WSSecurityEngineResult>();

        // Find the part of the security result that matches the given action
        for (WSSecurityEngineResult wsSecurityEngineResult : wsSecurityEngineResults) {
            // Check the result of every action whether it matches the given action
            WSSecurityEngineResult result = (WSSecurityEngineResult) wsSecurityEngineResult;
            int resultAction = (Integer) result.get(WSSecurityEngineResult.TAG_ACTION);
            if (resultAction == action) {
                wsResult.add(wsSecurityEngineResult);
            }
        }

        return wsResult.toArray(new WSSecurityEngineResult[wsResult
                .size()]);
    }
    
    private boolean isRefIdPresent(ArrayList refList , QName qname) {

        for (Object aRefList : refList) {
            WSDataRef dataRef = (WSDataRef) aRefList;

            //ArrayList can contain null elements
            if (dataRef == null) {
                continue;
            }
            //QName of the decrypted element
            QName dataRefQName = dataRef.getName();

            if (dataRefQName != null && dataRefQName.equals(qname)) {
                return true;
            }

        }
        
        return false;
        
    }

    
}
