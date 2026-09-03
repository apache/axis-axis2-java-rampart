/*
 * Copyright 2004,2013 The Apache Software Foundation.
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

 package org.apache.rampart.handler;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;

import javax.security.auth.callback.Callback;
import javax.security.auth.callback.UnsupportedCallbackException;

import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.RampartConstants;
import org.apache.wss4j.binding.wss10.PasswordString;
import org.apache.wss4j.common.ext.WSPasswordCallback;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.handler.RequestData;
import org.apache.wss4j.dom.message.token.UsernameToken;
import org.apache.wss4j.stax.utils.WSSUtils;
import org.apache.wss4j.stax.validate.TokenContext;
import org.apache.wss4j.dom.validate.UsernameTokenValidator;


/**
 * Overriding the default UsernameTokenValidatorImpl provided by WSS4J because the
 * default implementation expects the user to provide the plain text password to
 * WSS4J for validation.
 * 
 */
public class RampartUsernameTokenValidator extends UsernameTokenValidator {
    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);

    /**
     * Verify a UsernameToken containing a plaintext password.
     * <p>
     * The callback is handed a <code>null</code> password and is expected to set the
     * password it holds for the user, which is then compared against the one received
     * on the wire. Passing the received password into the callback instead, and
     * returning without comparing anything, means every password authenticates every
     * user: a callback that follows the documented set-password contract overwrites
     * nothing and reports nothing, so there is no check left anywhere on this path.
     * Do not put <code>usernameToken.getPassword()</code> back into the callback.
     */
    @Override
    protected void verifyPlaintextPassword(UsernameToken usernameToken, RequestData data
    ) throws WSSecurityException {
        if (data.getCallbackHandler() == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILURE, "noCallback");
        }

        WSPasswordCallback pwCb = new WSPasswordCallback(usernameToken.getName(),
                null,
                usernameToken.getPasswordType(), 
                WSPasswordCallback.USERNAME_TOKEN);
        try {
            WSSUtils.doPasswordCallback(data.getCallbackHandler(), pwCb);
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }

        String expectedPassword = pwCb.getPassword();
        String receivedPassword = usernameToken.getPassword();
        // A callback that neither set a password nor threw has authenticated nobody.
        if (expectedPassword == null || receivedPassword == null) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
        if (!MessageDigest.isEqual(expectedPassword.getBytes(StandardCharsets.UTF_8),
                receivedPassword.getBytes(StandardCharsets.UTF_8))) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION);
        }
    }

}
