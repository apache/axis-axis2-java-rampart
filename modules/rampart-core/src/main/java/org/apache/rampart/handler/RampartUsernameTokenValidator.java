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
import org.apache.wss4j.stax.validate.UsernameTokenValidatorImpl;


/**
 * Overriding the default UsernameTokenValidatorImpl provided by WSS4J because the
 * default implementation expects the user to provide the plain text password to
 * WSS4J for validation.
 * 
 */
public class RampartUsernameTokenValidator extends UsernameTokenValidatorImpl {

    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);

    /**
     * Verify a UsernameToken containing a plaintext password.
     */
    @Override
    protected void verifyPlaintextPassword(
        String username,
        PasswordString passwordType,
        TokenContext tokenContext
    ) throws WSSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(username,
                null,
                passwordType.getType(),
                WSPasswordCallback.USERNAME_TOKEN);
        try {
            WSSUtils.doPasswordCallback(tokenContext.getWssSecurityProperties().getCallbackHandler(), pwCb);
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }

    }

}
