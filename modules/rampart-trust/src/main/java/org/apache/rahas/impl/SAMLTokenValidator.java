package org.apache.rahas.impl;

import java.security.PublicKey;
import java.security.cert.X509Certificate;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.impl.dom.jaxp.DocumentBuilderFactoryImpl;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TokenValidator;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.components.crypto.CryptoFactory;
import org.opensaml.SAMLAssertion;
import org.opensaml.SAMLException;
import org.w3c.dom.Element;

/**
 * Implementation of a SAML Token Validator for the Security Token Service.
 */
public class SAMLTokenValidator implements TokenValidator {

    Log log = LogFactory.getLog(SAMLTokenValidator.class);

    private String configFile;
    private OMElement configElement;
    private String configParamName;

    /**
     * Returns a SOAPEnvelope with the result of the validation.
     * 
     * @param data
     *                the RahasData object, containing information about the
     *                request.
     */
    public SOAPEnvelope validate(RahasData data) throws TrustException {
	// retrieve the message context
	MessageContext inMsgCtx = data.getInMessageContext();

	// retrieve the list of tokens from the message context
	TokenStorage tkStorage = TrustUtil.getTokenStore(inMsgCtx);

	try {
	    // Set the DOM impl to DOOM
	    DocumentBuilderFactoryImpl.setDOOMRequired(true);

	    // Create envelope
	    SOAPEnvelope env = TrustUtil.createSOAPEnvelope(inMsgCtx
		    .getEnvelope().getNamespace().getNamespaceURI());

	    // Create RSTR element, with respective version
	    OMElement rstrElem;
	    int wstVersion = data.getVersion();
	    if (RahasConstants.VERSION_05_02 == wstVersion) {
		rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
			wstVersion, env.getBody());
	    } else {
		OMElement rstrcElem = TrustUtil
			.createRequestSecurityTokenResponseCollectionElement(
				wstVersion, env.getBody());
		rstrElem = TrustUtil.createRequestSecurityTokenResponseElement(
			wstVersion, rstrcElem);
	    }

	    // Create TokenType element, set to RSTR/Status
	    TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
		    TrustUtil.getWSTNamespace(wstVersion)
			    + RahasConstants.TOK_TYPE_STATUS);

	    // Create Status element
	    OMElement statusElement = createMessageElement(wstVersion,
		    rstrElem, RahasConstants.LocalNames.STATUS);

	    // Obtain the token
	    Token tk = tkStorage.getToken(data.getTokenId());

	    // create the crypto object
	    PublicKey issuerPBKey = getIssuerPublicKey(inMsgCtx);

	    boolean valid = isValid(tk, issuerPBKey);
	    String validityCode;

	    if (valid) {
		validityCode = RahasConstants.STATUS_CODE_VALID;
	    } else {
		validityCode = RahasConstants.STATUS_CODE_INVALID;
	    }

	    // Create Code element (inside Status) and set it to the
	    // correspondent value
	    createMessageElement(wstVersion, statusElement,
		    RahasConstants.LocalNames.CODE).setText(
		    TrustUtil.getWSTNamespace(wstVersion) + validityCode);

	    return env;
	} finally {
	    DocumentBuilderFactoryImpl.setDOOMRequired(false);
	}
    }

    /**
     * Checks whether the token is valid or not, by verifying the issuer's own
     * signature. If it has been signed by the token issuer, then it is a valid
     * token.
     * 
     * @param token
     *                the token to validate.
     * @return true if the token has been signed by the issuer.
     */
    private boolean isValid(Token token, PublicKey issuerPBKey) {
	// extract SAMLAssertion object from token
	OMElement assertionOMElement = token.getToken();
	SAMLAssertion samlAssertion = null;

	try {
	    samlAssertion = new SAMLAssertion((Element) assertionOMElement);

	    log.info("Verifying token validity...");

	    // check if the token has been signed by the issuer.
	    samlAssertion.verify(issuerPBKey);

	} catch (SAMLException e) {
	    log.error("Could not verify signature", e);
	    return false;
	}

	// if there was no exception, then the token is valid
	return true;
    }

    //here we basically reuse the SAMLTokenIssuer config
    // to create the crypto object, so we can load the issuer's certificates
    private PublicKey getIssuerPublicKey(MessageContext inMsgCtx) {
	PublicKey issuerPBKey = null;
	SAMLTokenIssuerConfig config = null;

	try {
	    if (configElement != null) {
		config = new SAMLTokenIssuerConfig(
			configElement
				.getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
	    }

	    // Look for the file
	    if ((config == null) && (configFile != null)) {
		config = new SAMLTokenIssuerConfig(configFile);
	    }

	    // Look for the param
	    if ((config == null) && (configParamName != null)) {
		Parameter param = inMsgCtx.getParameter(configParamName);
		if ((param != null) && (param.getParameterElement() != null)) {
		    config = new SAMLTokenIssuerConfig(param
			    .getParameterElement().getFirstChildWithName(
				    SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
		} else {
		    throw new TrustException("expectedParameterMissing",
			    new String[] { configParamName });
		}
	    }

	    if (config == null) {
		throw new TrustException("configurationIsNull");
	    }

	    Crypto crypto;
	    if (config.cryptoElement != null) { // crypto props
		// defined as
		// elements
		crypto = CryptoFactory.getInstance(TrustUtil
			.toProperties(config.cryptoElement), inMsgCtx
			.getAxisService().getClassLoader());
	    } else { // crypto props defined in a properties file
		crypto = CryptoFactory.getInstance(config.cryptoPropertiesFile,
			inMsgCtx.getAxisService().getClassLoader());
	    }

	    X509Certificate[] issuerCerts = crypto
		    .getCertificates(config.issuerKeyAlias);

	    issuerPBKey = issuerCerts[0].getPublicKey();

	} catch (Exception e) {
	    log.error("Could not retrieve issuer public key", e);
	}
	return issuerPBKey;
    }

    /**
     * Returns the <wst:Status> element.
     * 
     * @param version
     *                WS-Trust version.
     * @param parent
     *                the parent OMElement.
     */
    private static OMElement createMessageElement(int version,
	    OMElement parent, String elementName) throws TrustException {
	return createOMElement(parent, TrustUtil.getWSTNamespace(version),
		elementName, RahasConstants.WST_PREFIX);
    }

    private static OMElement createOMElement(OMElement parent, String ns,
	    String ln, String prefix) {
	return parent.getOMFactory().createOMElement(new QName(ns, ln, prefix),
		parent);
    }

    // ========================================================================

    /**
     * Set the configuration file of this TokenValidator. <p/> This is the text
     * value of the &lt;configuration-file&gt; element of the
     * token-dispatcher-configuration
     * 
     * @param configFile
     */
    public void setConfigurationFile(String configFile) {
	this.configFile = configFile;
    }

    /**
     * Set the name of the configuration parameter. <p/> If this is used then
     * there must be a <code>org.apache.axis2.description.Parameter</code>
     * object available in the via the messageContext when the
     * <code>TokenValidator</code> is called.
     * 
     * @param configParamName
     * @see org.apache.axis2.description.Parameter
     */
    public void setConfigurationParamName(String configParamName) {
	this.configParamName = configParamName;
    }

    public void setConfigurationElement(OMElement configElement) {
	this.configElement = configElement;
    }

}
