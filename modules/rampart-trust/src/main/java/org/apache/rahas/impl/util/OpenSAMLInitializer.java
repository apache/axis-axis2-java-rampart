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
package org.apache.rahas.impl.util;

import org.apache.axis2.AxisFault;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.wss4j.common.saml.OpenSAMLUtil;
import org.opensaml.core.config.InitializationException;
import org.opensaml.core.config.InitializationService;

/**
 * One-time, process-wide initialisation of the OpenSAML stack used by WSS4J and Rahas.
 *
 * <p>RAMPART-459: OpenSAML's {@link InitializationService#initialize()} is
 * {@code static synchronized} and has no idempotency guard - every call reloads every
 * registered module initialiser. Calling it per message serialised all inbound
 * traffic on that class monitor, SAML policy or not. Callers on the message path must
 * use {@link #ensureInitialized()} instead of calling it directly.</p>
 *
 * <p>Ordering matters and must not be swapped: {@link OpenSAMLUtil#initSamlEngine()}
 * replaces OpenSAML's global {@code Configuration} with a fresh one holding only
 * WSS4J's provider registry, so anything initialised before it is discarded.
 * {@code InitializationService.initialize()} therefore runs second, populating that
 * configuration with the remaining OpenSAML modules (global security configuration,
 * xmlsec, parser pool). This is the state the per-message calls used to converge on
 * from the second message onwards; it is now reached on the first and left alone.</p>
 */
public final class OpenSAMLInitializer {

    private static final Log log = LogFactory.getLog(OpenSAMLInitializer.class);

    private static volatile boolean initialized;

    private OpenSAMLInitializer() {
    }

    /**
     * Fails module initialisation with a clear message when guava is missing.
     *
     * <p>OpenSAML, Shibboleth and WSS4J all need guava at runtime. Axis2 2.0.2 stopped
     * bundling it, so it now ships in the Rampart distribution's lib/; an installation
     * assembled by hand can easily miss it. Without this check the failure surfaces as
     * a NoClassDefFoundError deep inside OpenSAML, and Axis2 logs module init faults
     * only at INFO, so the reason is logged here at ERROR as well.</p>
     */
    public static void checkRuntimeDependencies() throws AxisFault {
        checkRuntimeDependencies(InitializationService.class.getClassLoader());
    }

    static void checkRuntimeDependencies(ClassLoader openSAMLLoader) throws AxisFault {
        try {
            Class.forName("com.google.common.base.Strings", false, openSAMLLoader);
        } catch (ClassNotFoundException | LinkageError e) {
            String message = "Google Guava is not on the classpath, but OpenSAML and WSS4J"
                    + " require it. Copy the guava and failureaccess jars from the Rampart"
                    + " distribution's lib/ directory into the Axis2 lib/ (or WEB-INF/lib)"
                    + " directory alongside the other Rampart dependencies.";
            log.error(message);
            throw new AxisFault(message, e);
        }
    }

    /**
     * Initialises OpenSAML once. After the first successful call this is a single
     * volatile read. A failed attempt is not recorded, so the next call retries.
     */
    public static void ensureInitialized() throws InitializationException {
        if (initialized) {
            return;
        }
        synchronized (OpenSAMLInitializer.class) {
            if (initialized) {
                return;
            }
            OpenSAMLUtil.initSamlEngine();
            InitializationService.initialize();
            initialized = true;
            if (log.isDebugEnabled()) {
                log.debug("OpenSAML initialization complete");
            }
        }
    }
}
