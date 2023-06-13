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
import org.opensaml.core.config.ConfigurationService;
import org.opensaml.core.config.InitializationService;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistry;

/**
 * Rampart specific SAML bootstrap class. Here we set parser pool to
 * axiom specific one.
 */
public class RampartSAMLBootstrap extends InitializationService {
    protected RampartSAMLBootstrap() {
        super();
    }

    public static synchronized void initialize() throws InitializationException {
        InitializationService.initialize();
        initializeParserPool();

    }

    protected static void initializeParserPool() throws InitializationException {

        AxiomParserPool pp = new AxiomParserPool();
        pp.setMaxPoolSize(50);
        try {
            pp.initialize();
        } catch (Exception e) {
            throw new InitializationException("Error initializing axiom based parser pool", e);
        }
        ConfigurationService.get(XMLObjectProviderRegistry.class).setParserPool(pp);

    }
}
