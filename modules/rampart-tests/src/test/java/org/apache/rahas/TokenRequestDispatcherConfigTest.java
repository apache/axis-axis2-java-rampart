/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.rahas;

import java.io.InputStream;

import junit.framework.TestCase;

public class TokenRequestDispatcherConfigTest extends TestCase {

    /**
     * Stands in for an Axis2 service class loader: it defines the issuer class itself,
     * as a service archive carries a class the rahas module loader cannot see.
     */
    private static final class ServiceClassLoader extends ClassLoader {

        ServiceClassLoader(ClassLoader parent) {
            super(parent);
        }

        @Override
        protected Class<?> loadClass(String name, boolean resolve) throws ClassNotFoundException {
            if (!TempIssuer.class.getName().equals(name)) {
                return super.loadClass(name, resolve);
            }
            Class<?> loaded = findLoadedClass(name);
            if (loaded == null) {
                try (InputStream in = getParent().getResourceAsStream(
                        name.replace('.', '/') + ".class")) {
                    if (in == null) {
                        throw new ClassNotFoundException(name);
                    }
                    byte[] bytes = in.readAllBytes();
                    loaded = defineClass(name, bytes, 0, bytes.length);
                } catch (java.io.IOException e) {
                    throw new ClassNotFoundException(name, e);
                }
            }
            return loaded;
        }
    }

    public TokenRequestDispatcherConfigTest() {
        super();
    }

    public TokenRequestDispatcherConfigTest(String arg0) {
        super(arg0);
    }

    /**
     * Testing a valid config file
     */
    public void testWithConfigFile() throws Exception {
        TokenRequestDispatcherConfig config = TokenRequestDispatcherConfig
                .load("test-resources/trust/dispatcher.config.xml");

        assertEquals("Incorrect default issuer class name",
                "org.apache.rahas.TempIssuer", config
                        .getDefaultIssuerName());

        TokenIssuer issuer = config
                .getIssuer("http://example.org/mySpecialToken1");

        assertEquals("Incorrect issuer for token type : "
                + "http://example.org/mySpecialToken1", TempIssuer.class
                .getName(), issuer.getClass().getName());
    }

    /**
     * RAMPART-397: the issuer is loaded with the configured service class loader, so a
     * class that only the service archive carries is found.
     */
    public void testIssuerLoadedWithServiceClassLoader() throws Exception {
        TokenRequestDispatcherConfig config = TokenRequestDispatcherConfig
                .load("test-resources/trust/dispatcher.config.xml");
        ServiceClassLoader serviceLoader = new ServiceClassLoader(getClass().getClassLoader());
        config.setClassLoader(serviceLoader);

        TokenIssuer issuer = config.getIssuer("http://example.org/mySpecialToken1");

        assertSame("issuer must come from the service class loader",
                serviceLoader, issuer.getClass().getClassLoader());
        assertNotSame("the service loader's own definition must be used",
                TempIssuer.class, issuer.getClass());
        assertSame("default issuer must use the same loader",
                serviceLoader, config.getDefaultIssuerInstace().getClass().getClassLoader());
    }

    /**
     * Testing expected faliure when the default issuer is not specified
     */
    public void testInvalidCOnfigWithMissingDefaultIssuer() {
        try {
            TokenRequestDispatcherConfig
                .load("test-resources/trust/dispatcher.config.invalid.1.xml");
            fail("This should fail since there's no default isser specified");
        } catch (TrustException e) {
            assertEquals("Incorrect error", TrustException.getMessage(
                    "defaultIssuerMissing", null), e.getMessage());
        }
    }

    /**
     * Testing expected faliure when the tokenType value is missing from a 
     * tokenType definition
     */
    public void testInvalidRequestTypeDef() {
        try {
            TokenRequestDispatcherConfig
                .load("test-resources/trust/dispatcher.config.invalid.2.xml");
            fail("This should fail since there is an invalid " +
                    "requestType definition");
        } catch (TrustException e) {
            assertEquals("Incorrect error", TrustException.getMessage(
                    "invalidTokenTypeDefinition", new String[] { "Issuer",
                            TempIssuer.class.getName() }), e.getMessage());
        }
    }
}
