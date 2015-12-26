package org.apache.rahas.impl.util;

import org.apache.axiom.util.UIDGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rahas.RahasConstants;
import org.apache.rahas.TrustException;
import org.apache.ws.security.components.crypto.Crypto;
import org.apache.ws.security.message.WSSecEncryptedKey;
import org.apache.ws.security.util.Base64;
import org.apache.xml.security.signature.XMLSignature;
import org.apache.xml.security.utils.EncryptionConstants;
import org.joda.time.DateTime;
import org.opensaml.Configuration;
import org.opensaml.saml1.core.*;
import org.opensaml.ws.wssecurity.KeyIdentifier;
import org.opensaml.ws.wssecurity.SecurityTokenReference;
import org.opensaml.ws.wssecurity.WSSecurityConstants;
import org.opensaml.xml.encryption.CipherData;
import org.opensaml.xml.encryption.CipherValue;
import org.opensaml.xml.encryption.EncryptedKey;
import org.opensaml.xml.encryption.EncryptionMethod;
import org.opensaml.xml.io.MarshallingException;
import org.opensaml.xml.schema.XSString;
import org.opensaml.xml.schema.impl.XSStringBuilder;
import org.opensaml.xml.security.SecurityHelper;
import org.opensaml.xml.security.credential.Credential;
import org.opensaml.xml.signature.*;
import org.w3c.dom.Document;
import org.w3c.dom.Element;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

/**
 * Utility class for SAML 1 assertions. Responsible for manipulating all SAML1 specific objects
 * like Assertion, ConfirmationMethod etc ...
 */
public class SAMLUtils {

    private static final Log log = LogFactory.getLog(SAMLUtils.class);

    @SuppressWarnings({"UnusedDeclaration"})
    public static Collection<X509Certificate> getCertChainCollection(X509Certificate[] issuerCerts) {
        ArrayList<X509Certificate> certCollection = new ArrayList<X509Certificate>();

        if (issuerCerts == null) {
            return certCollection;
        } else {
            Collections.addAll(certCollection, issuerCerts);
        }

        return certCollection;
    }

    /**
     * Builds an assertion from an XML element.
     * @param assertionElement The XML element.
     * @return An Assertion object.
     */
    public static Assertion buildAssertion(Element assertionElement) {

       return (Assertion) Configuration.getBuilderFactory().
               getBuilder(Assertion.DEFAULT_ELEMENT_NAME).buildObject(assertionElement);

    }

/**
     * Signs the SAML assertion. The steps to sign SAML assertion is as follows,
     * <ol>
     *     <li>Get certificate for issuer alias</li>
     *     <li>Extract private key</li>
     *     <li>Create {@link org.opensaml.xml.security.credential.Credential} object</li>
     *     <li>Create {@link org.opensaml.xml.signature.Signature} object</li>
     *     <li>Set Signature object in Assertion</li>
     *     <li>Prepare signing environment - SecurityHelper.prepareSignatureParams</li>
     *     <li>Perform signing action - Signer.signObject</li>
     * </ol>
     * @param assertion The assertion to be signed.
     * @param crypto Certificate and private key data are stored in Crypto object
     * @param issuerKeyAlias Key alias
     * @param issuerKeyPassword Key password
     * @throws TrustException If an error occurred while signing the assertion.
     */
    public static void signAssertion(Assertion assertion, Crypto crypto,
                                     String issuerKeyAlias, String issuerKeyPassword)
            throws TrustException {

        X509Certificate issuerCerts = CommonUtil.getCertificateByAlias(crypto, issuerKeyAlias);

        String signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_RSA;

        PublicKey issuerPublicKey = issuerCerts.getPublicKey();

        String publicKeyAlgorithm = issuerPublicKey.getAlgorithm();
        if (publicKeyAlgorithm.equalsIgnoreCase("DSA")) {
            signatureAlgorithm = XMLSignature.ALGO_ID_SIGNATURE_DSA;
        }

        PrivateKey issuerPrivateKey;
        try {
            issuerPrivateKey = crypto.getPrivateKey(
                    issuerKeyAlias, issuerKeyPassword);
        } catch (Exception e) {
            log.debug("Unable to get issuer private key for issuer alias " + issuerKeyAlias);
            throw new TrustException("issuerPrivateKeyNotFound", new Object[]{issuerKeyAlias});
        }

        Credential signingCredential = SecurityHelper.getSimpleCredential(issuerPublicKey, issuerPrivateKey);

        Signature signature = (Signature) CommonUtil.buildXMLObject(Signature.DEFAULT_ELEMENT_NAME);
        signature.setCanonicalizationAlgorithm(SignatureConstants.ALGO_ID_C14N_EXCL_OMIT_COMMENTS);
        signature.setSigningCredential(signingCredential);
        signature.setSignatureAlgorithm(signatureAlgorithm);

        X509Data x509Data = CommonUtil.createX509Data(issuerCerts);
        KeyInfo keyInfo = createKeyInfo(x509Data);

        signature.setKeyInfo(keyInfo);
        assertion.setSignature(signature);

        try {

            Document document = CommonUtil.getOMDOMDocument();

            Configuration.getMarshallerFactory().getMarshaller(assertion).marshall(assertion, document);
        } catch (MarshallingException e) {
            log.debug("Error while marshalling assertion ", e);
            throw new TrustException("errorMarshallingAssertion", e);
        }

        try {
            Signer.signObject(signature);
        } catch (SignatureException e) {
            log.debug("Error signing SAML Assertion. An error occurred while signing SAML Assertion with alias "
                    + issuerKeyAlias, e);
            throw new TrustException("errorSigningAssertion", e);
        }
    }

    /**
     * Get subject confirmation method of the given SAML 1.1 Assertion.
     * This is used in rampart-core.
     * @param assertion SAML 1.1 Assertion
     * @return subject confirmation method
     */
    public static String getSAML11SubjectConfirmationMethod(Assertion assertion) {
        String subjectConfirmationMethod = RahasConstants.SAML11_SUBJECT_CONFIRMATION_HOK;
        // iterate the statements and get the subject confirmation method.
        List<Statement> statements = assertion.getStatements();

        // TODO check whether there is an efficient method of doing this
        if (!statements.isEmpty()) {
            SubjectStatement subjectStatement = (SubjectStatement) statements.get(0);
            Subject subject = subjectStatement.getSubject();

            if (subject != null) {
                SubjectConfirmation subjectConfirmation = subject.getSubjectConfirmation();

                if (subjectConfirmation != null) {
                    List<ConfirmationMethod> confirmationMethods = subjectConfirmation.getConfirmationMethods();

                    if (!confirmationMethods.isEmpty()) {
                        subjectConfirmationMethod = confirmationMethods.get(0).getConfirmationMethod();
                    }
                }
            }
        }


        return subjectConfirmationMethod;
    }

    /**
     * Create named identifier.
     * @param principalName Name of the subject.
     * @param format Format of the subject, whether it is an email, uid etc ...
     * @return The NamedIdentifier object.
     * @throws org.apache.rahas.TrustException If unable to find the builder.
     */
    public static NameIdentifier createNamedIdentifier(String principalName, String format) throws TrustException{

        NameIdentifier nameId = (NameIdentifier)CommonUtil.buildXMLObject(NameIdentifier.DEFAULT_ELEMENT_NAME);
        nameId.setNameIdentifier(principalName);
        nameId.setFormat(format);

        return nameId;
    }

    /**
     * Creates the subject confirmation method.
     * Relevant XML element would look like as follows,
     * <saml:ConfirmationMethod>
     *       urn:oasis:names:tc:SAML:1.0:cm:holder-of-key
     *  </saml:ConfirmationMethod>
     * @param confirmationMethod Name of the actual confirmation method. Could be
     *      holder-of-key - "urn:oasis:names:tc:SAML:1.0:cm:holder-of-key"
     *      sender-vouches - "urn:oasis:names:tc:SAML:1.0:cm:sender-vouches"
     *      bearer - TODO
     * @return Returns the opensaml representation of the ConfirmationMethod.
     * @throws TrustException If unable to find appropriate XMLObject builder for confirmation QName.
     */
    public static ConfirmationMethod createSubjectConfirmationMethod(final String confirmationMethod)
            throws TrustException {

        ConfirmationMethod confirmationMethodObject
                = (ConfirmationMethod)CommonUtil.buildXMLObject(ConfirmationMethod.DEFAULT_ELEMENT_NAME);
        confirmationMethodObject.setConfirmationMethod(confirmationMethod);

        return confirmationMethodObject;
    }

    /**
     * Creates opensaml SubjectConfirmation representation. The relevant XML would looks as follows,
     *  <saml:SubjectConfirmation>
     *       <saml:ConfirmationMethod>
     *           urn:oasis:names:tc:SAML:1.0:cm:sender-vouches
     *       </saml:ConfirmationMethod>
     *   </saml:SubjectConfirmation>
     * @param confirmationMethod The subject confirmation method. Bearer, Sender-Vouches or Holder-Of-Key.
     * @param keyInfoContent The KeyInfo content. According to SPEC (SAML 1.1) this could be null.
     * @return OpenSAML representation of SubjectConfirmation.
     * @throws TrustException If unable to find any of the XML builders.
     */
    public static SubjectConfirmation createSubjectConfirmation(final String confirmationMethod,
                                                          KeyInfo keyInfoContent) throws TrustException {

        SubjectConfirmation subjectConfirmation
                = (SubjectConfirmation)CommonUtil.buildXMLObject(SubjectConfirmation.DEFAULT_ELEMENT_NAME);

        ConfirmationMethod method = SAMLUtils.createSubjectConfirmationMethod(confirmationMethod);
        subjectConfirmation.getConfirmationMethods().add(method);

        if (keyInfoContent != null) {
            subjectConfirmation.setKeyInfo(keyInfoContent);
        }

        return subjectConfirmation;
    }

    /**
     * Creates an opensaml Subject representation. The relevant XML would looks as follows,
     * <saml:Subject>
     *       <saml:NameIdentifier
     *       NameQualifier="www.example.com"
     *       Format="...">
     *       uid=joe,ou=people,ou=saml-demo,o=baltimore.com
     *       </saml:NameIdentifier>
     *       <saml:SubjectConfirmation>
     *           <saml:ConfirmationMethod>
     *           urn:oasis:names:tc:SAML:1.0:cm:holder-of-key
     *           </saml:ConfirmationMethod>
     *       <ds:KeyInfo>
     *           <ds:KeyValue>...</ds:KeyValue>
     *       </ds:KeyInfo>
     *       </saml:SubjectConfirmation>
     *   </saml:Subject>
     * @param nameIdentifier Represent the "NameIdentifier" of XML element above.
     * @param confirmationMethod Represent the bearer, HOK or Sender-Vouches.
     * @param keyInfoContent Key info information. This could be null.
     * @return OpenSAML representation of the Subject.
     * @throws TrustException If a relevant XML builder is unable to find.
     */
    public static Subject createSubject(final NameIdentifier nameIdentifier, final String confirmationMethod,
                                                          KeyInfo keyInfoContent) throws TrustException {

        Subject subject = (Subject)CommonUtil.buildXMLObject(Subject.DEFAULT_ELEMENT_NAME);
        subject.setNameIdentifier(nameIdentifier);

        SubjectConfirmation subjectConfirmation
                = SAMLUtils.createSubjectConfirmation(confirmationMethod,keyInfoContent);
        subject.setSubjectConfirmation(subjectConfirmation);

        return subject;
    }

    /**
     * Creates an AuthenticationStatement. The relevant XML element looks as follows,
     * <AuthenticationStatement
     *       AuthenticationInstant="2003-04-17T00:46:00Z"
     *       AuthenticationMethod="urn:oasis:names:tc:SAML:1.0:am:password">
     *       <Subject>
     *           <NameIdentifier
     *           Format="urn:oasis:names:tc:SAML:1.1:nameid-format:emailAddress">
     *           scott@example.org</NameIdentifier>
     *               <SubjectConfirmation>
     *                   <ConfirmationMethod>urn:oasis:names:tc:SAML:1.0:cm:bearer</ConfirmationMethod>
     *               </SubjectConfirmation>
     *       </Subject>
     *       <SubjectLocality IPAddress="127.0.0.1"/>
     *   </AuthenticationStatement>
     * @param subject OpenSAML Subject implementation.
     * @param authenticationMethod How subject is authenticated ? i.e. by using a password, kerberos, certificate
     *          etc ... The method is defined as a URL in SAML specification.
     * @param authenticationInstant Time which authentication took place.
     * @return opensaml AuthenticationStatement object.
     * @throws org.apache.rahas.TrustException If unable to find the builder.
     */
    public static AuthenticationStatement createAuthenticationStatement(Subject subject, String authenticationMethod,
                                                                    DateTime authenticationInstant)
                                                                    throws TrustException {

        AuthenticationStatement authenticationStatement
                = (AuthenticationStatement)CommonUtil.buildXMLObject(AuthenticationStatement.DEFAULT_ELEMENT_NAME);

        authenticationStatement.setSubject(subject);
        authenticationStatement.setAuthenticationMethod(authenticationMethod);
        authenticationStatement.setAuthenticationInstant(authenticationInstant);

        return authenticationStatement;
    }

    /**Creates an attribute statement. Sample attribute statement would look like follows,
     *  <saml:AttributeStatement>
     *       <saml:Subject>
     *           <saml:NameIdentifier
     *               NameQualifier="www.example.com"
     *               Format="...">
     *               uid=joe,ou=people,ou=saml-demo,o=baltimore.com
     *           </saml:NameIdentifier>
     *           <saml:SubjectConfirmation>
     *               <saml:ConfirmationMethod>
     *               urn:oasis:names:tc:SAML:1.0:cm:holder-of-key
     *               </saml:ConfirmationMethod>
     *               <ds:KeyInfo>
     *                 <ds:KeyValue>...</ds:KeyValue>
     *               </ds:KeyInfo>
     *           </saml:SubjectConfirmation>
     *       </saml:Subject>
     *       <saml:Attribute
     *           AttributeName="MemberLevel"
     *           AttributeNamespace="http://www.oasis.open.org/Catalyst2002/attributes">
     *           <saml:AttributeValue>gold</saml:AttributeValue>
     *       </saml:Attribute>
     *       <saml:Attribute
     *           AttributeName="E-mail"
     *           AttributeNamespace="http://www.oasis.open.org/Catalyst2002/attributes">
     *           <saml:AttributeValue>joe@yahoo.com</saml:AttributeValue>
     *       </saml:Attribute>
     *   </saml:AttributeStatement>
     *
     * @param subject The OpenSAML representation of the Subject.
     * @param attributeList List of attribute values to include within the message.
     * @return OpenSAML representation of AttributeStatement.
     * @throws org.apache.rahas.TrustException If unable to find the appropriate builder.
     */
    public static AttributeStatement createAttributeStatement(Subject subject, List<Attribute> attributeList)
            throws TrustException {

        AttributeStatement attributeStatement
                = (AttributeStatement)CommonUtil.buildXMLObject(AttributeStatement.DEFAULT_ELEMENT_NAME);

        attributeStatement.setSubject(subject);
        attributeStatement.getAttributes().addAll(attributeList);

        return attributeStatement;
    }

    /**
     * Creates Conditions object. Analogous XML element is as follows,
     * <saml:Conditions>
     *       NotBefore="2002-06-19T16:53:33.173Z"
     *       NotOnOrAfter="2002-06-19T17:08:33.173Z"/>
     * @param notBefore The validity of the Assertion starts from this value.
     * @param notOnOrAfter The validity ends from this value.
     * @return OpenSAML Conditions object.
     * @throws org.apache.rahas.TrustException If unable to find appropriate builder.
     */
    public static Conditions createConditions(DateTime notBefore, DateTime notOnOrAfter) throws TrustException {

        Conditions conditions = (Conditions)CommonUtil.buildXMLObject(Conditions.DEFAULT_ELEMENT_NAME);

        conditions.setNotBefore(notBefore);
        conditions.setNotOnOrAfter(notOnOrAfter);

        return conditions;
    }

    /**
     * This method creates the final SAML assertion. The final SAML assertion would looks like as follows,
     *  <saml:Assertion  AssertionID="_a75adf55-01d7-40cc-929f-dbd8372ebdfc"
     *                   IssueInstant="2003-04-17T00:46:02Z"
     *                   Issuer=”www.opensaml.org”
     *                   MajorVersion="1"
     *                   MinorVersion="1"
     *                   xmlns="urn:oasis:names:tc:SAML:1.0:assertion">
     *       <saml:Conditions>
     *           NotBefore="2002-06-19T16:53:33.173Z"
     *           NotOnOrAfter="2002-06-19T17:08:33.173Z"/>
     *       <saml:AttributeStatement>
     *           <saml:Subject>
     *               <saml:NameIdentifier
     *                       NameQualifier="www.example.com"
     *                       Format="...">
     *                       uid=joe,ou=people,ou=saml-demo,o=baltimore.com
     *               </saml:NameIdentifier>
     *               <saml:SubjectConfirmation>
     *                   <saml:ConfirmationMethod>
     *                       urn:oasis:names:tc:SAML:1.0:cm:holder-of-key
     *                   </saml:ConfirmationMethod>
     *                   <ds:KeyInfo>
     *                       <ds:KeyValue>...</ds:KeyValue>
     *                   </ds:KeyInfo>
     *               </saml:SubjectConfirmation>
     *           </saml:Subject>
     *           <saml:Attribute
     *               AttributeName="MemberLevel"
     *               AttributeNamespace="http://www.oasis.open.org/Catalyst2002/attributes">
     *               <saml:AttributeValue>gold</saml:AttributeValue>
     *           </saml:Attribute>
     *           <saml:Attribute
     *               AttributeName="E-mail" AttributeNamespace="http://www.oasis.open.org/Catalyst2002/attributes">
     *               <saml:AttributeValue>joe@yahoo.com</saml:AttributeValue>
     *           </saml:Attribute>
     *       </saml:AttributeStatement>
     *       <ds:Signature>...</ds:Signature>
     *   </saml:Assertion>
     * @param issuerName Represents the "Issuer" in Assertion.
     * @param notBefore The Condition's NotBefore value
     * @param notOnOrAfter The Condition's NotOnOrAfter value
     * @param statements  Other statements.
     * @return An opensaml Assertion object.
     * @throws org.apache.rahas.TrustException If unable to find the appropriate builder.
     */
    public static Assertion createAssertion(String issuerName, DateTime notBefore, DateTime notOnOrAfter,
                                        List<Statement> statements) throws TrustException {

        Assertion assertion = (Assertion)CommonUtil.buildXMLObject(Assertion.DEFAULT_ELEMENT_NAME);

        assertion.setIssuer(issuerName);
        assertion.setConditions(SAMLUtils.createConditions(notBefore, notOnOrAfter));
        assertion.getStatements().addAll(statements);
        assertion.setID(UIDGenerator.generateUID());
        assertion.setIssueInstant(new DateTime());
        return assertion;
    }

    /**
     * Creates a SAML attribute similar to following,
     * <saml:Attribute
     *       AttributeName="MemberLevel"
     *       AttributeNamespace="http://www.oasis.open.org/Catalyst2002/attributes">
     *       <saml:AttributeValue>gold</saml:AttributeValue>
     *   </saml:Attribute>
     * @param name attribute name
     * @param namespace attribute namespace.
     * @param value attribute value.
     * @return OpenSAML representation of the attribute.
     * @throws org.apache.rahas.TrustException If unable to find the appropriate builder.
     */
    public static Attribute createAttribute(String name, String namespace, String value) throws TrustException {

        Attribute attribute = (Attribute)CommonUtil.buildXMLObject(Attribute.DEFAULT_ELEMENT_NAME);

        attribute.setAttributeName(name);
        attribute.setAttributeNamespace(namespace);

        XSStringBuilder attributeValueBuilder = (XSStringBuilder)Configuration.getBuilderFactory().
                getBuilder(XSString.TYPE_NAME);

        XSString stringValue
                = attributeValueBuilder.buildObject(AttributeValue.DEFAULT_ELEMENT_NAME, XSString.TYPE_NAME);
        stringValue.setValue(value);

        attribute.getAttributeValues().add(stringValue);

        return attribute;

    }

    /**
     * Creates a KeyInfo object
     * @return OpenSAML KeyInfo representation.
     * @throws TrustException If an error occurred while creating KeyInfo.
     */
    public static KeyInfo createKeyInfo() throws TrustException {

        return (KeyInfo)CommonUtil.buildXMLObject(KeyInfo.DEFAULT_ELEMENT_NAME);
    }

     /**
     * Creates a KeyInfo element given EncryptedKey. The relevant XML would looks as follows,
     *  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
     *     <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
     *           ....
     *     </xenc:EncryptedKey>
     *   </ds:KeyInfo>
     * @param encryptedKey The OpemSAML representation of encrypted key.
     * @return The appropriate opensaml representation of the KeyInfo.
     * @throws org.apache.rahas.TrustException If unable to find the builder.
     */
    public static KeyInfo createKeyInfo(EncryptedKey encryptedKey) throws TrustException {

        KeyInfo keyInfo = createKeyInfo();
        keyInfo.getEncryptedKeys().add(encryptedKey);

        return keyInfo;
    }

    /**
     * Creates a KeyInfo element given EncryptedKey. The relevant XML would looks as follows,
     *  <KeyInfo xmlns="http://www.w3.org/2000/09/xmldsig#">
     *     <X509Data xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
     *           ....
     *     </X509Data>
     *   </ds:KeyInfo>
     * @param x509Data The OpemSAML representation X509Data
     * @return The appropriate opensaml representation of the KeyInfo.
     * @throws org.apache.rahas.TrustException If unable to find the builder.
     */
    public static KeyInfo createKeyInfo(X509Data x509Data) throws TrustException {

        KeyInfo keyInfo = createKeyInfo();
        keyInfo.getX509Datas().add(x509Data);

        return keyInfo;
    }



    /**
     * This method will created the "EncryptedKey" of a SAML assertion.
     * An encrypted key would look like as follows,
     * <xenc:EncryptedKey xmlns:xenc="http://www.w3.org/2001/04/xmlenc#"
     *    xmlns:ds="http://www.w3.org/2000/09/xmldsig#"
     *   Id="EncKeyId-E5CEA44F9C25F55C4913269595550814">
     *    <xenc:EncryptionMethod Algorithm="http://www.w3.org/2001/04/xmlenc#rsa-1_5"/>
     *    <ds:KeyInfo>
     *      <wsse:SecurityTokenReference
     *        xmlns:wsse="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-wssecurity-secext-1.0.xsd">
     *      <wsse:KeyIdentifier
     *             EncodingType="http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0
     *             #Base64Binary"
     *             ValueType="http://docs.oasis-open.org/wss/oasis-wss-soap-message-security-1.1#ThumbprintSHA1">
     *             a/jhNus21KVuoFx65LmkW2O/l10=
     *       </wsse:KeyIdentifier>
     *     </wsse:SecurityTokenReference>
     *    </ds:KeyInfo>
     *    <xenc:CipherData>
     *       <xenc:CipherValue>
     *             dnP0MBHiMLlSmnjJhGFs/I8/z...
     *        </xenc:CipherValue>
     *     </xenc:CipherData>
     *  </xenc:EncryptedKey>
     * @param certificate Certificate which holds the public key to encrypt ephemeral key.
     * @param wsSecEncryptedKey WS Security object which contains encrypted ephemeral key.
     *          TODO Passing WSSecEncryptedKey is an overhead. We should be able to create encrypted ephemeral
     *          key without WSS4J
     * @return OpenSAML EncryptedKey representation.
     * @throws TrustException If an error occurred while creating EncryptedKey.
     */
    static EncryptedKey createEncryptedKey(X509Certificate certificate, WSSecEncryptedKey wsSecEncryptedKey)
            throws TrustException {

        SecurityTokenReference securityTokenReference
                = (SecurityTokenReference)CommonUtil.buildXMLObject(SecurityTokenReference.ELEMENT_NAME);

        KeyIdentifier keyIdentifier = (KeyIdentifier)CommonUtil.buildXMLObject(KeyIdentifier.ELEMENT_NAME);

        // Encoding type set to http://docs.oasis-open.org/wss/2004/01/oasis-200401-wss-soap-message-security-1.0
        // #Base64Binary
        keyIdentifier.setEncodingType(KeyIdentifier.ENCODING_TYPE_BASE64_BINARY);
        keyIdentifier.setValueType(WSSecurityConstants.WS_SECURITY11_NS+"#ThumbprintSHA1");
        keyIdentifier.setValue(getThumbprintSha1(certificate));

        securityTokenReference.getUnknownXMLObjects().add(keyIdentifier);

        KeyInfo keyInfo = SAMLUtils.createKeyInfo();
        keyInfo.getXMLObjects().add(securityTokenReference);

        CipherValue cipherValue = (CipherValue)CommonUtil.buildXMLObject(CipherValue.DEFAULT_ELEMENT_NAME);
        cipherValue.setValue(Base64.encode(wsSecEncryptedKey.getEncryptedEphemeralKey()));

        CipherData cipherData = (CipherData)CommonUtil.buildXMLObject(CipherData.DEFAULT_ELEMENT_NAME);
        cipherData.setCipherValue(cipherValue);

        EncryptionMethod encryptionMethod = (EncryptionMethod)CommonUtil.buildXMLObject(EncryptionMethod.DEFAULT_ELEMENT_NAME);
        encryptionMethod.setAlgorithm(EncryptionConstants.ALGO_ID_KEYTRANSPORT_RSA15);

        EncryptedKey encryptedKey = (EncryptedKey)CommonUtil.buildXMLObject(EncryptedKey.DEFAULT_ELEMENT_NAME);

        encryptedKey.setID(wsSecEncryptedKey.getId());
        encryptedKey.setEncryptionMethod(encryptionMethod);
        encryptedKey.setCipherData(cipherData);
        encryptedKey.setKeyInfo(keyInfo);

        return encryptedKey;

    }

    private static String getThumbprintSha1(X509Certificate cert) throws TrustException {

        MessageDigest sha;
        try {
            sha = MessageDigest.getInstance("SHA-1");
        } catch (NoSuchAlgorithmException e1) {
            throw new TrustException("sha1NotFound", e1);
        }
        sha.reset();
        try {
            sha.update(cert.getEncoded());
        } catch (CertificateEncodingException e1) {
            throw new TrustException("certificateEncodingError", e1);
        }
        byte[] data = sha.digest();

        return Base64.encode(data);
    }

}

