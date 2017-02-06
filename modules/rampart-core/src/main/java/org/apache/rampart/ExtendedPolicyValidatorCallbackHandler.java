package org.apache.rampart;

import org.apache.ws.security.WSSecurityEngineResult;

import java.util.List;

/**
 * This is an extension of the PolicyValidatorCallbackHandler. PolicyValidatorCallbackHandler uses Vector
 * to pass processing results. But Lists are better than Vectors as its performance is better. Therefore we
 * introduce a new method in ExtendedPolicyValidatorCallbackHandler. Since we do not want to change the original
 * interface (as it might cause existing users to change their code) we are introducing a new interface.
 */
public interface ExtendedPolicyValidatorCallbackHandler extends PolicyValidatorCallbackHandler {

  /**
    * Validate policy based results.
    *
    * @param data validator data
    * @param results policy based ws-security results
    * @throws RampartException Rampart exception
    */
   public abstract void validate(ValidatorData data, List<WSSecurityEngineResult> results) throws RampartException;
}
