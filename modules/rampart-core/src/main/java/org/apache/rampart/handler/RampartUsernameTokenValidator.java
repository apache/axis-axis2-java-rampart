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
import org.apache.wss4j.dom.validate.UsernameTokenValidator;


/**
 * Overriding the default UsernameTokenValidatorImpl provided by WSS4J because the
 * default implementation expects the user to provide the plain text password to
 * WSS4J for validation.
 * 
 */
public class RampartUsernameTokenValidator extends UsernameTokenValidator { // BLBLBL can't inherit from stax, - wss4j.dom.validate expected
    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);

    /**
     * Verify a UsernameToken containing a plaintext password.
     */
    @Override
    protected void verifyPlaintextPassword(UsernameToken usernameToken, RequestData data
    ) throws WSSecurityException {
        WSPasswordCallback pwCb = new WSPasswordCallback(usernameToken.getName(),
        		usernameToken.getPassword(),
                usernameToken.getPasswordType(), 
                WSPasswordCallback.USERNAME_TOKEN);
        try {
            WSSUtils.doPasswordCallback(data.getCallbackHandler(), pwCb);
        } catch (WSSecurityException e) {
            throw new WSSecurityException(WSSecurityException.ErrorCode.FAILED_AUTHENTICATION, e);
        }

    }

}
