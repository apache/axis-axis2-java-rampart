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

import org.apache.axis2.client.Options;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.kernel.http.HTTPConstants;
import org.apache.rampart.util.RampartUtil;

/**
 * RAMPART-450: the token request to the STS must go through the proxy and
 * connection settings of the service request, while the service's own HTTP
 * credentials and the Rampart policy stay behind. The values are opaque to the
 * copy, so placeholders stand in for the transport's own property classes.
 */
public class StsClientTransportSettingsTest extends MessageBuilderTestBase {

    public void testProxyAndConnectionSettingsAreInherited() throws Exception {
        MessageContext ctx = getMsgCtx();
        Options serviceOptions = ctx.getOptions();

        Object proxy = new Object();
        serviceOptions.setProperty(HTTPConstants.PROXY, proxy);
        serviceOptions.setProperty(HTTPConstants.SO_TIMEOUT, 5000);
        serviceOptions.setProperty(HTTPConstants.CONNECTION_TIMEOUT, 2000);
        serviceOptions.setProperty(HTTPConstants.CHUNKED, Boolean.FALSE);
        serviceOptions.setTimeOutInMilliSeconds(42000);

        Options stsOptions = new Options();
        RampartUtil.inheritTransportSettings(ctx, stsOptions);

        assertSame(proxy, stsOptions.getProperty(HTTPConstants.PROXY));
        assertEquals(5000, stsOptions.getProperty(HTTPConstants.SO_TIMEOUT));
        assertEquals(2000, stsOptions.getProperty(HTTPConstants.CONNECTION_TIMEOUT));
        assertEquals(Boolean.FALSE, stsOptions.getProperty(HTTPConstants.CHUNKED));
        assertEquals(42000, stsOptions.getTimeOutInMilliSeconds());
    }

    public void testSettingsFromTheConfigurationContextAreInheritedToo() throws Exception {
        MessageContext ctx = getMsgCtx();
        Object proxy = new Object();
        ctx.getConfigurationContext().setProperty(HTTPConstants.PROXY, proxy);

        Options stsOptions = new Options();
        RampartUtil.inheritTransportSettings(ctx, stsOptions);

        assertSame(proxy, stsOptions.getProperty(HTTPConstants.PROXY));
    }

    public void testServiceCredentialsHeadersAndPolicyStayBehind() throws Exception {
        MessageContext ctx = getMsgCtx();
        Options serviceOptions = ctx.getOptions();
        serviceOptions.setProperty(HTTPConstants.AUTHENTICATE, new Object());
        serviceOptions.setProperty(HTTPConstants.HTTP_HEADERS, new java.util.ArrayList<Object>());
        serviceOptions.setProperty(HTTPConstants.COOKIE_STRING, "JSESSIONID=1");
        serviceOptions.setProperty(RampartMessageData.KEY_RAMPART_POLICY,
                loadPolicy("test-resources/policy/rampart-asymm-binding-6-3des-r15.xml"));
        serviceOptions.setProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN, "#tok");

        Options stsOptions = new Options();
        RampartUtil.inheritTransportSettings(ctx, stsOptions);

        assertNull(stsOptions.getProperty(HTTPConstants.AUTHENTICATE));
        assertNull(stsOptions.getProperty(HTTPConstants.HTTP_HEADERS));
        assertNull(stsOptions.getProperty(HTTPConstants.COOKIE_STRING));
        assertNull(stsOptions.getProperty(RampartMessageData.KEY_RAMPART_POLICY));
        assertNull(stsOptions.getProperty(RampartMessageData.KEY_CUSTOM_ISSUED_TOKEN));
    }
}
