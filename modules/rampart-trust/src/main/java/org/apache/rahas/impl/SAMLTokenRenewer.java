package org.apache.rahas.impl;

import java.time.Instant;
import java.time.ZoneOffset;
import java.time.ZonedDateTime;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMNode;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.RahasData;
import org.apache.rahas.Token;
import org.apache.rahas.TokenRenewer;
import org.apache.rahas.TokenStorage;
import org.apache.rahas.TrustException;
import org.apache.rahas.TrustUtil;
import org.apache.rahas.impl.util.CommonUtil;
import org.apache.rahas.impl.util.SAMLUtils;
import org.opensaml.saml.saml1.core.Assertion;
import org.opensaml.saml.saml1.core.Conditions;
import org.apache.wss4j.common.crypto.Crypto;
import org.apache.wss4j.common.util.DateUtil;
import org.apache.wss4j.dom.util.WSSecurityUtil;
import org.w3c.dom.Element;
import org.w3c.dom.Node;

@SuppressWarnings({"UnusedDeclaration"})
public class SAMLTokenRenewer implements TokenRenewer {
    
    private String configParamName;

    private OMElement configElement;

    private String configFile;

    public SOAPEnvelope renew(RahasData data) throws TrustException {

        // retrieve the message context
        MessageContext inMsgCtx = data.getInMessageContext();

        SAMLTokenIssuerConfig config = null;
        if (this.configElement != null) {
            config = new SAMLTokenIssuerConfig(configElement
                    .getFirstChildWithName(SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
        }

        // Look for the file
        if (config == null && this.configFile != null) {
            config = new SAMLTokenIssuerConfig(this.configFile);
        }

        // Look for the param
        if (config == null && this.configParamName != null) {
            Parameter param = inMsgCtx.getParameter(this.configParamName);
            if (param != null && param.getParameterElement() != null) {
                config = new SAMLTokenIssuerConfig(param
                        .getParameterElement().getFirstChildWithName(
                                SAMLTokenIssuerConfig.SAML_ISSUER_CONFIG));
            } else {
                throw new TrustException("expectedParameterMissing",
                        new String[]{this.configParamName});
            }
        }

        if (config == null) {
            throw new TrustException("configurationIsNull");
        }

        // retrieve the list of tokens from the message context
        TokenStorage tkStorage = TrustUtil.getTokenStore(inMsgCtx);

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

        ClassLoader classLoader = inMsgCtx.getAxisService().getClassLoader();
        Crypto crypto = config.getIssuerCrypto(classLoader);

        // Create TokenType element
        TrustUtil.createTokenTypeElement(wstVersion, rstrElem).setText(
                RahasConstants.TOK_TYPE_SAML_10);

        // Creation and expiration times
        ZonedDateTime creationTime = ZonedDateTime.now(ZoneOffset.UTC);
        ZonedDateTime expirationTime = ZonedDateTime.ofInstant(Instant.ofEpochMilli(creationTime.toInstant().toEpochMilli() + config.getTtl()), ZoneOffset.UTC);

        // Add the Lifetime element
        TrustUtil.createLifetimeElement(wstVersion, rstrElem, DateUtil.getDateTimeFormatter(true).format(creationTime), DateUtil.getDateTimeFormatter(true).format(expirationTime));

        // Obtain the token
        Token tk = tkStorage.getToken(data.getTokenId());

        OMElement assertionOMElement = tk.getToken();
        Assertion samlAssertion;

        samlAssertion = SAMLUtils.buildAssertion((Element) assertionOMElement);

        if (samlAssertion.getConditions() == null) {
            samlAssertion.setConditions((Conditions) CommonUtil.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME));

        }

        samlAssertion.getConditions().setNotBefore(creationTime.toInstant());
        samlAssertion.getConditions().setNotOnOrAfter(creationTime.toInstant());

        // sign the assertion
        SAMLUtils.signAssertion(samlAssertion, crypto, config.getIssuerKeyAlias(), config.getIssuerKeyPassword());

        // Create the RequestedSecurityToken element and add the SAML token
        // to it
        OMElement reqSecTokenElem = TrustUtil
                .createRequestedSecurityTokenElement(wstVersion, rstrElem);

        Node tempNode = samlAssertion.getDOM();
        reqSecTokenElem.addChild((OMNode) ((Element) rstrElem)
                .getOwnerDocument().importNode(tempNode, true));

        return env;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationFile(String configFile) {
        this.configFile = configFile;

    }
    
    /**
     * {@inheritDoc}
     */
    public void setConfigurationElement(OMElement configElement) {
        this.configElement = configElement;
    }

    /**
     * {@inheritDoc}
     */
    public void setConfigurationParamName(String configParamName) {
        this.configParamName = configParamName;
    }


}
