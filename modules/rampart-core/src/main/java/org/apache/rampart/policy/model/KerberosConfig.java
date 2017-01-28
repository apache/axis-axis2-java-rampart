/*
 * Copyright 2001-2014 The Apache Software Foundation.
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
package org.apache.rampart.policy.model;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;
import javax.xml.stream.XMLStreamWriter;

import org.apache.neethi.Assertion;
import org.apache.neethi.Constants;
import org.apache.neethi.PolicyComponent;
import org.apache.rampart.RampartException;
import org.ietf.jgss.GSSCredential;

/**
 * Container for Kerberos configuration options.
 */
public class KerberosConfig implements Assertion {

    public final static String KERBEROS_LN = RampartConfig.KERBEROS_CONFIG;

    public final static String JAAS_CONTEXT_LN = "jaasContext";

    public final static String PRINCIPAL_NAME_LN = "principalName";

    public final static String PRINCIPAL_PASSWORD_LN = "principalPassword";

    public final static String SERVICE_PRINCIPAL_NAME_LN = "servicePrincipalName";

    public final static String SERVICE_PRINCIPAL_NAME_FORM_LN = "servicePrincipalNameForm";

    public final static String KERBEROS_TOKEN_DECODER_CLASS_LN = "kerberosTokenDecoderClass";
    
    public final static String REQUEST_CREDENTIAL_DELEGATION_LN  = "requestCredentialDelegation";
    
    public final static String DELEGATION_CREDENTIAL_LN = "delegationCredential";

    /**
     * Specifies that the service principal name should be interpreted as a 
     * "host-based" name as specified in GSS API RFC, 
     * section "4.1: Host-Based Service Name Form". 
     * See <a href="http://www.ietf.org/rfc/rfc2743.txt">rfc2743 - GSS
     * API, Version 2</a>.
     */
    public final static String HOST_BASED_NAME_FORM = "hostbased";

    /**
     * Specifies that the service principal name should be interpreted as a   
     * "username" name as specified in GSS API RFC,
     * section "4.2: User Name Form". 
     * See <a href="http://www.ietf.org/rfc/rfc2743.txt">rfc2743 - GSS API, Version
     * 2</a>.
     */
    public final static String USERNAME_NAME_FORM = "username";

    private String jaasContext;

    private String principalName;

    private String principalPassword;

    private String servicePrincipalName;

    private String servicePrincipalNameForm;

    private String kerberosTokenDecoderClass;
    
    private boolean requstCredentialDelegation;
    
    private GSSCredential delegationCredential;
    
    /**
     * @return The JAAS context name to use to obtain a TGT (Ticket granting ticket).
     */
    public String getJaasContext() {
        return jaasContext;
    }

    /**
     * Sets the JAAS context name to use to obtain a TGT (Ticket granting ticket).
     * @param jaasContext the jaasContext to set
     */
    public void setJaasContext(String jaasContext) {
        this.jaasContext = jaasContext;
    }

    /**
     * @return The principal name to use to obtain a TGT (Ticket granting ticket).
     * This is usually the domain username.
     * If not specified, Rampart will fall back to the Rampart configuration's 
     * {@link RampartConfig#getUser() user}.
     * Note that the principal name specified in JAAS configuration takes precedence
     * over any principal name configured here.
     */
    public String getPrincipalName() {
        return principalName;
    }

    /**
     * Sets the principal name to use to obtain a TGT (Ticket granting ticket). 
     * This is usually the domain username. If* not specified, Rampart will fall back 
     * to the Rampart configuration's {@link RampartConfig#getUser() user}. 
     * Note that the principal name specified in JAAS configuration takes precedence 
     * over any principal name configured via this method.
     * @param principalName the principalName to set
     */
    public void setPrincipalName(String principalName) {
        this.principalName = principalName;
    }

    /**
     * @return Returns the principal's clear-text password. If the password is not
     * configured (null), Rampart will try to obtain it from any configured 
     * {@link RampartConfig#getPwCbClass() password callback}. Note that any 
     * principal password configured here will be ignored if the JAAS configuration 
     * configures usage of a keytab file.
     */
    public String getPrincipalPassword() {
        return principalPassword;
    }

    /**
     * Sets the principal's clear-text password. If the password is not configured
     * (null), Rampart will try to obtain it from any configured 
     * {@link RampartConfig#getPwCbClass() password callback}. Note that any 
     * principal password configured here will be ignored if the JAAS configuration 
     * configures usage of a keytab file.
     */
    public void setPrincipalPassword(String principalPassword) {
        this.principalPassword = principalPassword;
    }

    /**
     * @return The service principal name to use to obtain a service ticket on the 
     * client-side. Note that by default,
     * this name is assumed to be in a {@link #HOST_BASED_NAME_FORM} unless the
     * {@link #setServicePrincipalNameForm(String) service principal name form} is 
     * explicitly configured.
     */
    public String getServicePrincipalName() {
        return servicePrincipalName;
    }

    /**
     * Sets service principal name to use to obtain a service ticket on the 
     * client-side. Note that by default, this name is assumed to be in a 
     * {@link #HOST_BASED_NAME_FORM} unless the 
     * {@link #setServicePrincipalNameForm(String)
     * service principal name form} is explicitly configured.
     */
    public void setServicePrincipalName(String servicePrincipalName) {
        this.servicePrincipalName = servicePrincipalName;
    }

    /**
     * Returns the service principal name form.
     * @return Either {@value #HOST_BASED_NAME_FORM} or {@value #USERNAME_NAME_FORM}.   
     * Default is: {@value #HOST_BASED_NAME_FORM}.
     */
    public String getServicePrincipalNameForm() {
        if (servicePrincipalNameForm == null) {
            return HOST_BASED_NAME_FORM;
        }
        return servicePrincipalNameForm;
    }
    
    /**
     * Configures a Kerberos token decoder implementation for decoding Kerberos v5 tokens on server side.
     * The decoder will be used only if the Kerberos client/server session key cannot be obtained using Java's {@link com.sun.security.jgss.ExtendedGSSContext} API,
     * which is normally the case when using Java version older than 1.7.0_b07, 
     * see <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6710360"> JDK-6710360 : export Kerberos session key to applications</a>.
     * <p>
     * The class will be loaded using current service's {@link org.apache.axis2.description.AxisService#getClassLoader() classloader}.
     * </p>
     * 
     * @param kerberosTokenValidatorClass A fully qualifier class name that implements {@link org.apache.ws.security.validate.KerberosTokenValidator}.
     */
    public void setKerberosTokenDecoderClass(String kerberosTokenDecoderClass) {
        this.kerberosTokenDecoderClass = kerberosTokenDecoderClass;
    }
    
    /**
     * Returns the Kerberos token decoder implementation for decoding Kerberos v5 tokens on server side.
     * The decoder will be used only if the Kerberos client/server session key cannot be obtained using Java's {@link com.sun.security.jgss.ExtendedGSSContext} API,
     * which is normally the case when using Java version older than 1.7.0_b07, 
     * see <a href="http://bugs.java.com/bugdatabase/view_bug.do?bug_id=6710360"> JDK-6710360 : export Kerberos session key to applications</a>
     * 
     * @return A fully qualifier class name that implements {@link org.apache.ws.security.validate.KerberosTokenValidator} or <code>null</code> if no Kerberos token decoder is configured.
     */
    public String getKerberosTokenDecoderClass() {
        return this.kerberosTokenDecoderClass;
    }

    /**
     * Sets the service principal name form.
     * @param servicePrincipalNameForm The service principal name form to set. 
     * The given literal must be either {@value #HOST_BASED_NAME_FORM} or 
     * {@value #USERNAME_NAME_FORM}.
     * @throws IllegalArgumentException If the given 
     * <code>servicePrincipalNameForm</code> is not one of:
     * {@value #HOST_BASED_NAME_FORM} or {@value #USERNAME_NAME_FORM}.
     */
    public void setServicePrincipalNameForm(String servicePrincipalNameForm) 
        throws IllegalArgumentException {

        if (!HOST_BASED_NAME_FORM.equals(servicePrincipalNameForm) &&
            !USERNAME_NAME_FORM.equals(servicePrincipalNameForm)) {
            throw new IllegalArgumentException(
               new RampartException("invalidServicePrincipalNameForm", 
                                    new String[] {
                                        servicePrincipalNameForm, 
                                        HOST_BASED_NAME_FORM, 
                                        USERNAME_NAME_FORM }));
        }
        this.servicePrincipalNameForm = servicePrincipalNameForm;
    }
    
    /**
     * If Kerberos credential delegation is requested, the initiator's TGT (Ticket granting ticket) is propagated to the receiver
     * along with the TGS(Ticket granting service).
     * 
     * @return true if credential delegation is requested.
     */
    public boolean isRequstCredentialDelegation() {
        return requstCredentialDelegation;
    }

    /**
     * Enables Kerberos credential delegation. If credential delegation is requested, the initiator's TGT (Ticket
     * granting ticket) is propagated to the receiver along with the TGS(Ticket granting service). <br/>
     * <br/>
     * 
     * Enabling delegation requires <b>forwardable=true</b> property to be added to the <b>[libdefaults]</b> section in
     * the Kerberos setup configuration.KDC should also be explicitly configured to allow delegation as it is considered
     * a security issue and is disabled by default.
     * 
     * @param requstCredentialDelegation if true, credential delegation is requested.
     */
    public void setRequstCredentialDelegation(boolean requstCredentialDelegation) {
        this.requstCredentialDelegation = requstCredentialDelegation;
    }

    /**
     * The delegation credential is available when the initiator has explicitly requested delegation through
     * {@link KerberosConfig#setRequstCredentialDelegation(boolean)} and the receiver has retrieved it and set it
     * through {@link KerberosConfig#setDelegationCredential(GSSCredential)}.
     * 
     * If available, the delegation credential is used by the receiver to obtain a service ticket for another
     * Kerberos protected WS on behalf of the initiator. The receiver's principal must have explicit privileges to use
     * the delegated credential(TGT) for retrieval of the service ticket.
     * 
     * @return the client's TGT wrapped in {@link GSSCredential}
     */
    public GSSCredential getDelegationCredential() {
        return delegationCredential;
    }

    /**
     * Sets the delegation credential to be used by the receiver to obtain a service ticket for another
     * Kerberos protected WS on behalf of the initiator. The receiver's principal must have explicit privileges to use
     * the delegated credential(TGT) for retrieval of the service ticket.
     * 
     * @param delegationCredential the {@link GSSCredential} to use for obtaining a TGS
     */
    public void setDelegationCredential(GSSCredential delegationCredential) {
        this.delegationCredential = delegationCredential;
    }

    public PolicyComponent normalize() {
        throw new UnsupportedOperationException();
    }

    public QName getName() {
        return new QName(RampartConfig.NS, KERBEROS_LN);
    }

    public boolean isOptional() {
        return true;
    }

    public boolean isIgnorable() {
        throw new UnsupportedOperationException();
    }

    public short getType() {
        return Constants.TYPE_ASSERTION;
    }

    public boolean equal(PolicyComponent policyComponent) {
        throw new UnsupportedOperationException();
    }

    public void serialize(XMLStreamWriter writer) throws XMLStreamException {
        String prefix = writer.getPrefix(RampartConfig.NS);

        if (prefix == null) {
            prefix = RampartConfig.NS;
            writer.setPrefix(prefix, RampartConfig.NS);
        }

        if (getJaasContext() != null) {
            writer.writeStartElement(RampartConfig.NS, JAAS_CONTEXT_LN);
            writer.writeCharacters(getJaasContext());
            writer.writeEndElement();
        }

        if (getPrincipalName() != null) {
            writer.writeStartElement(RampartConfig.NS, PRINCIPAL_NAME_LN);
            writer.writeCharacters(getPrincipalName());
            writer.writeEndElement();
        }

        if (getPrincipalPassword() != null) {
            writer.writeStartElement(RampartConfig.NS, PRINCIPAL_PASSWORD_LN);
            writer.writeCharacters(getPrincipalPassword());
            writer.writeEndElement();
        }

        if (getServicePrincipalName() != null) {
            writer.writeStartElement(RampartConfig.NS, SERVICE_PRINCIPAL_NAME_LN);
            writer.writeCharacters(getServicePrincipalName());
            writer.writeEndElement();
        }

        if (this.servicePrincipalNameForm != null) {
            writer.writeStartElement(RampartConfig.NS,
                                     SERVICE_PRINCIPAL_NAME_FORM_LN);
            writer.writeCharacters(this.servicePrincipalNameForm);
            writer.writeEndElement();
        }
        
        if (this.kerberosTokenDecoderClass != null) {
            writer.writeStartElement(RampartConfig.NS,
                                     KERBEROS_TOKEN_DECODER_CLASS_LN);
            writer.writeCharacters(this.kerberosTokenDecoderClass);
            writer.writeEndElement();
        }
        
        if (this.requstCredentialDelegation) {
            writer.writeStartElement(RampartConfig.NS, REQUEST_CREDENTIAL_DELEGATION_LN);
            writer.writeCharacters(Boolean.toString(this.requstCredentialDelegation));
            writer.writeEndElement();
        }
    }
}
