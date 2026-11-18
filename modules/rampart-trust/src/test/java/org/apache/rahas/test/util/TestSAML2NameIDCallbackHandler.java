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

package org.apache.rahas.test.util;

import org.apache.rahas.TrustException;
import org.apache.rahas.impl.util.SAMLCallback;
import org.apache.rahas.impl.util.SAMLCallbackHandler;
import org.apache.rahas.impl.util.SAMLNameIdentifierCallback;
import org.apache.rahas.impl.util.SAML2Utils;
import org.opensaml.saml.common.SAMLException;
import org.opensaml.saml.saml2.core.NameID;

/**
 * Supplies a SAML 2.0 subject NameID with a non-default Format and ignores
 * every other callback, so attribute statements fall back to the defaults.
 */
public class TestSAML2NameIDCallbackHandler implements SAMLCallbackHandler {

    public static final String VALUE = "subject-from-handler";
    public static final String FORMAT = NameID.PERSISTENT;

    public void handle(SAMLCallback callback) throws SAMLException {
        if (callback.getCallbackType() == SAMLCallback.NAME_IDENTIFIER_CALLBACK) {
            try {
                ((SAMLNameIdentifierCallback) callback).setSAML2NameID(
                        SAML2Utils.createNamedIdentifier(VALUE, FORMAT));
            } catch (TrustException e) {
                throw new SAMLException("Error creating the NameID", e);
            }
        }
    }
}
