package org.apache.rampart;

import java.util.List;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.ietf.jgss.GSSCredential;

/**
 * 
 */
public class KerberosDelegationServiceValidator extends PolicyBasedResultsValidator {
    
    private static GSSCredential delegationCredential = null;

    @Override
    public void validate(ValidatorData data, List<WSSecurityEngineResult> results) throws RampartException {

        super.validate(data, results);
        

        for (WSSecurityEngineResult wsSecEngineResult : results) {
            Integer actInt = (Integer) wsSecEngineResult.get(WSSecurityEngineResult.TAG_ACTION);
            if (actInt == WSConstants.BST) {                
                delegationCredential = (GSSCredential) wsSecEngineResult.
                                get(WSSecurityEngineResult.TAG_DELEGATION_CREDENTIAL);
                break;
            }
        }
    }
    
    static GSSCredential getDelegationCredential(){
        return delegationCredential;
    }

}
