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
package org.apache.rampart;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;
import java.util.concurrent.CountDownLatch;

import junit.framework.TestCase;

import org.apache.axis2.description.AxisService;
import org.apache.rampart.handler.RampartUsernameTokenValidator;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.wss4j.dom.validate.UsernameTokenValidator;

/**
 * RAMPART-427: adding the locked CLIENT_SIDE marker parameter to a service must be
 * idempotent and safe under concurrent first requests; otherwise all but the first
 * thread fails with "The CLIENT_SIDE parameter is already locked and the value
 * cannot be overridden".
 */
public class RampartMessageDataTest extends TestCase {

    /**
     * Deterministic guard: a second add must not throw because the parameter is
     * already present and locked.
     */
    public void testAddClientSideParameterIsIdempotent() throws Exception {
        AxisService service = new AxisService("TestService");
        RampartMessageData.addClientSideParameterIfAbsent(service);
        RampartMessageData.addClientSideParameterIfAbsent(service);
        assertNotNull("CLIENT_SIDE parameter should be present",
                service.getParameter(RampartMessageData.PARAM_CLIENT_SIDE));
    }

    /**
     * Many threads racing to mark the same service client-side must all succeed,
     * with the parameter added exactly once.
     */
    public void testAddClientSideParameterConcurrent() throws Exception {
        final AxisService service = new AxisService("TestService");
        final int threadCount = 16;
        final CountDownLatch startGate = new CountDownLatch(1);
        final CountDownLatch doneGate = new CountDownLatch(threadCount);
        final List<Throwable> failures = new CopyOnWriteArrayList<Throwable>();

        for (int i = 0; i < threadCount; i++) {
            new Thread(new Runnable() {
                public void run() {
                    try {
                        startGate.await();
                        RampartMessageData.addClientSideParameterIfAbsent(service);
                    } catch (Throwable t) {
                        failures.add(t);
                    } finally {
                        doneGate.countDown();
                    }
                }
            }).start();
        }

        startGate.countDown(); // release all threads at once to maximise contention
        doneGate.await();

        assertTrue("concurrent CLIENT_SIDE add must not fail (RAMPART-427): " + failures,
                failures.isEmpty());
        assertNotNull("CLIENT_SIDE parameter should be present",
                service.getParameter(RampartMessageData.PARAM_CLIENT_SIDE));
    }

    /** A stand-in for a validator that delegates to an external password store. */
    public static class ExternalUsernameTokenValidator extends UsernameTokenValidator {
    }

    /** RAMPART-460: without the setting the default validator stays in place. */
    public void testDefaultUsernameTokenValidator() throws Exception {
        assertEquals(RampartUsernameTokenValidator.class,
                RampartMessageData.getUsernameTokenValidatorClass(null, null));
        assertEquals(RampartUsernameTokenValidator.class,
                RampartMessageData.getUsernameTokenValidatorClass(new RampartConfig(), null));
    }

    /** RAMPART-460: a configured validator replaces the default. */
    public void testConfiguredUsernameTokenValidator() throws Exception {
        RampartConfig config = new RampartConfig();
        config.setUsernameTokenValidatorClass(ExternalUsernameTokenValidator.class.getName());
        assertEquals(ExternalUsernameTokenValidator.class,
                RampartMessageData.getUsernameTokenValidatorClass(config, null));
        assertEquals(ExternalUsernameTokenValidator.class,
                RampartMessageData.getUsernameTokenValidatorClass(config,
                        getClass().getClassLoader()));
    }

    /** A configured class that is missing must fail, not fall back to the default. */
    public void testMissingUsernameTokenValidatorFails() {
        RampartConfig config = new RampartConfig();
        config.setUsernameTokenValidatorClass("org.example.NoSuchValidator");
        try {
            RampartMessageData.getUsernameTokenValidatorClass(config, null);
            fail("a missing validator class must be rejected");
        } catch (RampartException expected) {
        }
    }

    /** A configured class that is not a WSS4J Validator must fail up front. */
    public void testNonValidatorClassFails() {
        RampartConfig config = new RampartConfig();
        config.setUsernameTokenValidatorClass(String.class.getName());
        try {
            RampartMessageData.getUsernameTokenValidatorClass(config, null);
            fail("a class that is not a Validator must be rejected");
        } catch (RampartException expected) {
        }
    }
}
