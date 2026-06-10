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

import javax.xml.namespace.QName;

import junit.framework.TestCase;

import org.apache.neethi.builders.PrimitiveAssertion;
import org.apache.ws.secpolicy.SP11Constants;
import org.apache.ws.secpolicy.SP12Constants;

public class RahasModuleTest extends TestCase {

    /**
     * RAMPART-371: rahas registers (in module.xml) for the WS-SecurityPolicy 1.2
     * namespace and is the only module registered for it, so it must report that it
     * can support assertions in that namespace. Otherwise Axis2 policy validation
     * fails with "atleast one module can't support {...200702}SupportingTokens".
     */
    public void testSupportsWsSecurityPolicy12Namespace() {
        Rahas rahas = new Rahas();
        assertTrue("rahas must support WS-SecurityPolicy 1.2 (200702) assertions",
                rahas.canSupportAssertion(new PrimitiveAssertion(
                        new QName(SP12Constants.SP_NS, "SupportingTokens"))));
    }

    public void testSupportsWsSecurityPolicy11Namespace() {
        Rahas rahas = new Rahas();
        assertTrue("rahas must support WS-SecurityPolicy 1.1 assertions",
                rahas.canSupportAssertion(new PrimitiveAssertion(
                        new QName(SP11Constants.SP_NS, "SupportingTokens"))));
    }

    public void testDoesNotSupportUnrelatedAssertions() {
        Rahas rahas = new Rahas();
        assertFalse("rahas must not claim support for unrelated namespaces",
                rahas.canSupportAssertion(new PrimitiveAssertion(
                        new QName("http://example.com/unknown", "Foo"))));
        assertFalse("null assertion must not be supported",
                rahas.canSupportAssertion(null));
    }
}
