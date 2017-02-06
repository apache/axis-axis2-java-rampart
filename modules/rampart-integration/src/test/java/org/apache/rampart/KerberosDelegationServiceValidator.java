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

import java.util.List;

import org.apache.ws.security.WSConstants;
import org.apache.ws.security.WSSecurityEngineResult;
import org.ietf.jgss.GSSCredential;

public class KerberosDelegationServiceValidator extends PolicyBasedResultsValidator {
    private static GSSCredential delegationCredential;

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
