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

import java.net.URL;
import java.net.URLClassLoader;
import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;
import java.util.concurrent.atomic.AtomicInteger;

import junit.framework.TestCase;

import org.apache.axis2.AxisFault;

import org.opensaml.core.config.InitializationException;
import org.opensaml.core.xml.config.XMLObjectProviderRegistrySupport;
import org.opensaml.xmlsec.SecurityConfigurationSupport;
import org.opensaml.xmlsec.SignatureSigningConfiguration;

/**
 * RAMPART-459: OpenSAML must be initialised once, not on every message, and must end
 * up in the same state the per-message calls used to converge on.
 */
public class OpenSAMLInitializerTest extends TestCase {

    public void testInitialisesWss4jAndOpenSAMLModules() throws Exception {
        OpenSAMLInitializer.ensureInitialized();

        assertNotNull("unmarshaller factory must be available",
                XMLObjectProviderRegistrySupport.getUnmarshallerFactory());
        // Registered by an OpenSAML module initialiser, not by WSS4J; present only if
        // InitializationService ran after initSamlEngine replaced the configuration.
        assertNotNull("OpenSAML global security configuration must be registered",
                SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration());
    }

    /**
     * Each InitializationService run registers fresh global configuration objects, so
     * an unchanged instance across calls shows the module initialisers did not re-run.
     */
    public void testRepeatedCallsDoNotReinitialise() throws Exception {
        OpenSAMLInitializer.ensureInitialized();
        SignatureSigningConfiguration before =
                SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration();

        OpenSAMLInitializer.ensureInitialized();
        OpenSAMLInitializer.ensureInitialized();

        assertSame("OpenSAML must not be re-initialised on later calls", before,
                SecurityConfigurationSupport.getGlobalSignatureSigningConfiguration());
    }

    public void testRuntimeDependencyCheckPassesWithGuava() throws Exception {
        OpenSAMLInitializer.checkRuntimeDependencies();
    }

    /** A missing guava must fail module init with a message naming the jars to add. */
    public void testRuntimeDependencyCheckFailsWithoutGuava() throws Exception {
        ClassLoader withoutGuava = new URLClassLoader(new URL[0], null);
        try {
            OpenSAMLInitializer.checkRuntimeDependencies(withoutGuava);
            fail("a classpath without guava must fail the check");
        } catch (AxisFault expected) {
            assertTrue(expected.getMessage(), expected.getMessage().contains("guava"));
        }
    }

    /**
     * A failed attempt must not be retried per message: that put every thread back on
     * the lock to fail the same way, for deployments that never use SAML.
     */
    public void testFailureIsRecordedAndNotRetried() throws Exception {
        final AtomicInteger attempts = new AtomicInteger();
        final InitializationException cause = new InitializationException("parser pool");
        OpenSAMLInitializer initializer = new OpenSAMLInitializer(() -> {
            attempts.incrementAndGet();
            throw cause;
        });

        for (int i = 0; i < 3; i++) {
            try {
                initializer.ensure();
                fail("a failed initialisation must keep failing");
            } catch (InitializationException expected) {
                assertSame(cause, expected);
            }
        }
        assertEquals("initialisation must be attempted once", 1, attempts.get());
    }

    public void testUncheckedFailureIsWrappedAndNotRetried() throws Exception {
        final AtomicInteger attempts = new AtomicInteger();
        final IllegalArgumentException cause = new IllegalArgumentException("maxElementDepth");
        OpenSAMLInitializer initializer = new OpenSAMLInitializer(() -> {
            attempts.incrementAndGet();
            throw cause;
        });

        InitializationException first = null;
        for (int i = 0; i < 3; i++) {
            try {
                initializer.ensure();
                fail("a failed initialisation must keep failing");
            } catch (InitializationException expected) {
                assertSame(cause, expected.getCause());
                if (first == null) {
                    first = expected;
                }
                assertSame(first, expected);
            }
        }
        assertEquals("initialisation must be attempted once", 1, attempts.get());
    }

    public void testConcurrentCallsSucceed() throws Exception {
        final int threadCount = 16;
        final CountDownLatch startGate = new CountDownLatch(1);
        final CountDownLatch doneGate = new CountDownLatch(threadCount);
        final List<Throwable> failures = new CopyOnWriteArrayList<Throwable>();

        for (int i = 0; i < threadCount; i++) {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        startGate.await();
                        OpenSAMLInitializer.ensureInitialized();
                    } catch (Throwable t) {
                        failures.add(t);
                    } finally {
                        doneGate.countDown();
                    }
                }
            }).start();
        }

        startGate.countDown();
        doneGate.await();

        assertTrue("concurrent initialisation must not fail: " + failures, failures.isEmpty());
        assertNotNull(XMLObjectProviderRegistrySupport.getUnmarshallerFactory());
    }
}
