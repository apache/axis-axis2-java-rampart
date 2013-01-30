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
import org.apache.ws.security.WSPasswordCallback;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.handler.RequestData;
import org.apache.ws.security.message.token.UsernameToken;
import org.apache.ws.security.validate.UsernameTokenValidator;

/**
 * Overriding the default UsernameTokenValidator provided by WSS4J because the
 * default implementation expects the user to provide the plain text password to
 * WSS4J for validation.
 * 
 */
public class RampartUsernameTokenValidator extends UsernameTokenValidator {

	private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);

	@Override
	protected void verifyPlaintextPassword(UsernameToken usernameToken,
			RequestData data) throws WSSecurityException {

		String user = usernameToken.getName();
		String password = usernameToken.getPassword();
		String pwType = usernameToken.getPasswordType();

		// Provide the password to the user for validation
		WSPasswordCallback pwCb = new WSPasswordCallback(user, password,
				pwType, WSPasswordCallback.USERNAME_TOKEN, data);
		try {
			data.getCallbackHandler().handle(new Callback[] { pwCb });
		} catch (IOException e) {
			if (mlog.isDebugEnabled()) {
				mlog.debug(e);
			}
			throw new WSSecurityException(
					WSSecurityException.FAILED_AUTHENTICATION);
		} catch (UnsupportedCallbackException e) {
			if (mlog.isDebugEnabled()) {
				mlog.debug(e);
			}
			throw new WSSecurityException(
					WSSecurityException.FAILED_AUTHENTICATION);
		}

	}
}
