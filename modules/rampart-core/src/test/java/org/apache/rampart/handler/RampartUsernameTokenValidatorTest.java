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
package org.apache.rampart.handler;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.CallbackHandler;
import javax.xml.parsers.DocumentBuilderFactory;

import junit.framework.TestCase;

import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.w3c.dom.Document;

/**
 * Tests that a plaintext UsernameToken password is actually compared.
 *
 * <p>The validator used to hand the password received on the wire to the callback
 * and return, comparing nothing, so any password authenticated any user. These
 * tests pin the comparison: the callback is asked what the password should be, and
 * a token that does not carry that password is rejected.
 */
public class RampartUsernameTokenValidatorTest extends TestCase {

    private static final String USER = "alice";
    private static final String CORRECT_PASSWORD = "correct-horse";

    /** Follows the documented contract: sets the password it holds for the user. */
    private static class SetPasswordCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) {
            for (Callback callback : callbacks) {
                WSPasswordCallback pwcb = (WSPasswordCallback) callback;
                if (USER.equals(pwcb.getIdentifier())) {
                    pwcb.setPassword(CORRECT_PASSWORD);
                }
            }
        }
    }

    /** Sets nothing and throws nothing, so it has authenticated nobody. */
    private static class SilentCallbackHandler implements CallbackHandler {
        public void handle(Callback[] callbacks) {
        }
    }

    private UsernameToken usernameToken(String password) throws Exception {
        DocumentBuilderFactory factory = DocumentBuilderFactory.newInstance();
        factory.setNamespaceAware(true);
        Document doc = factory.newDocumentBuilder().newDocument();
        UsernameToken token = new UsernameToken(true, doc, WSConstants.PASSWORD_TEXT);
        token.setName(USER);
        token.setPassword(password);
        return token;
    }

    private void verify(UsernameToken token, CallbackHandler handler) throws WSSecurityException {
        RequestData data = new RequestData();
        data.setCallbackHandler(handler);
        new RampartUsernameTokenValidator().verifyPlaintextPassword(token, data);
    }

    public void testCorrectPasswordIsAccepted() throws Exception {
        verify(usernameToken(CORRECT_PASSWORD), new SetPasswordCallbackHandler());
    }

    public void testWrongPasswordIsRejected() throws Exception {
        try {
            verify(usernameToken("anything-else"), new SetPasswordCallbackHandler());
            fail("a UsernameToken carrying the wrong password must not authenticate");
        } catch (WSSecurityException expected) {
            assertEquals(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION,
                    expected.getErrorCode());
        }
    }

    /**
     * The case that made every password work: the callback overwrites nothing, so
     * whatever arrived on the wire must not be treated as verified.
     */
    public void testCallbackThatSetsNoPasswordIsRejected() throws Exception {
        try {
            verify(usernameToken("anything-at-all"), new SilentCallbackHandler());
            fail("a callback that set no password must not authenticate anyone");
        } catch (WSSecurityException expected) {
            assertEquals(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION,
                    expected.getErrorCode());
        }
    }

    public void testMissingCallbackHandlerIsRejected() throws Exception {
        try {
            verify(usernameToken(CORRECT_PASSWORD), null);
            fail("no callback handler means nothing can verify the password");
        } catch (WSSecurityException expected) {
            // expected
        }
    }
}
