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

package org.apache.rahas;

import org.apache.rahas.impl.util.AxiomParserPool;
import org.opensaml.Configuration;
import org.opensaml.DefaultBootstrap;
import org.opensaml.xml.ConfigurationException;
import org.opensaml.xml.parse.XMLParserException;

/**
 * Rampart specific SAML bootstrap class. Here we set parser pool to
 * axiom specific one.
 */
public class RampartSAMLBootstrap extends DefaultBootstrap {

     /** List of default XMLTooling configuration files. */
    private static String[] xmlToolingConfigs = {
        "/default-config.xml",
        "/schema-config.xml",
        "/signature-config.xml",
        "/signature-validation-config.xml",
        "/encryption-config.xml",
        "/encryption-validation-config.xml",
        "/soap11-config.xml",
        "/wsfed11-protocol-config.xml",
        "/saml1-assertion-config.xml",
        "/saml1-protocol-config.xml",
        "/saml1-core-validation-config.xml",
        "/saml2-assertion-config.xml",
        "/saml2-protocol-config.xml",
        "/saml2-core-validation-config.xml",
        "/saml1-metadata-config.xml",
        "/saml2-metadata-config.xml",
        "/saml2-metadata-validation-config.xml",
        "/saml2-metadata-attr-config.xml",
        "/saml2-metadata-idp-discovery-config.xml",
        "/saml2-metadata-ui-config.xml",
        "/saml2-protocol-thirdparty-config.xml",
        "/saml2-metadata-query-config.xml",
        "/saml2-assertion-delegation-restriction-config.xml",
        "/saml2-ecp-config.xml",
        "/xacml10-saml2-profile-config.xml",
        "/xacml11-saml2-profile-config.xml",
        "/xacml20-context-config.xml",
        "/xacml20-policy-config.xml",
        "/xacml2-saml2-profile-config.xml",
        "/xacml3-saml2-profile-config.xml",
        "/wsaddressing-config.xml",
        "/wssecurity-config.xml",
    };

    protected RampartSAMLBootstrap() {
        super();
    }

    public static synchronized void bootstrap() throws ConfigurationException {
        initializeXMLSecurity();

        initializeVelocity();

        initializeXMLTooling(xmlToolingConfigs);

        initializeArtifactBuilderFactories();

        initializeGlobalSecurityConfiguration();

        initializeParserPool();

        initializeESAPI();
    }

    protected static void initializeParserPool() throws ConfigurationException {

        AxiomParserPool pp = new AxiomParserPool();
        pp.setMaxPoolSize(50);
        try {
            pp.initialize();
        } catch (XMLParserException e) {
            throw new ConfigurationException("Error initializing axiom based parser pool", e);
        }
        Configuration.setParserPool(pp);

    }
}
