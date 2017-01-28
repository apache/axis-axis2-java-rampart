/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.rampart.policy.builders;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.neethi.Assertion;
import org.apache.neethi.AssertionBuilderFactory;
import org.apache.neethi.builders.AssertionBuilder;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;

/**
 * Builder for {@link KerberosConfig} assertion.
 */
public class KerberosConfigBuilder implements AssertionBuilder<OMElement> {
    public Assertion build(OMElement element, AssertionBuilderFactory factory) 
        throws IllegalArgumentException {

        KerberosConfig kerberosConfig = new KerberosConfig();

        OMElement childElement;

        childElement = element.getFirstChildWithName(
              new QName(RampartConfig.NS, KerberosConfig.JAAS_CONTEXT_LN));
        if (childElement != null) {
            if (null == kerberosConfig.getJaasContext()) {
                kerberosConfig.setJaasContext(childElement.getText().trim());
            }
        }

        childElement = element.getFirstChildWithName(
              new QName(RampartConfig.NS, KerberosConfig.PRINCIPAL_NAME_LN));
        if (childElement != null) {
            if (null == kerberosConfig.getPrincipalName()) {
                kerberosConfig.setPrincipalName(childElement.getText().trim());
            }
        }

        childElement = element.getFirstChildWithName(
            new QName(RampartConfig.NS, KerberosConfig.PRINCIPAL_PASSWORD_LN));
        if (childElement != null) {
            if (null == kerberosConfig.getPrincipalPassword()) {
                kerberosConfig.setPrincipalPassword(childElement.getText().trim());
            }
        }

        childElement = element.getFirstChildWithName(new QName(RampartConfig.NS,
            KerberosConfig.SERVICE_PRINCIPAL_NAME_LN));
        if (childElement != null) {
            kerberosConfig.setServicePrincipalName(childElement.getText().trim());
        }

        childElement = element.getFirstChildWithName(new QName(RampartConfig.NS,
            KerberosConfig.SERVICE_PRINCIPAL_NAME_FORM_LN));
        if (childElement != null) {
            kerberosConfig.setServicePrincipalNameForm(
                 childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(RampartConfig.NS,
            KerberosConfig.KERBEROS_TOKEN_DECODER_CLASS_LN));
        if (childElement != null) {
            kerberosConfig.setKerberosTokenDecoderClass(
                 childElement.getText().trim());
        }
        
        childElement = element.getFirstChildWithName(new QName(
            RampartConfig.NS, KerberosConfig.REQUEST_CREDENTIAL_DELEGATION_LN));
        if (childElement != null) {
            kerberosConfig.setRequstCredentialDelegation(Boolean.valueOf(childElement.getText().trim()));
        }    

        return kerberosConfig;
    }

    public QName[] getKnownElements() {
        return new QName[] {
            new QName(RampartConfig.NS, KerberosConfig.KERBEROS_LN) 
        };
    }
}

