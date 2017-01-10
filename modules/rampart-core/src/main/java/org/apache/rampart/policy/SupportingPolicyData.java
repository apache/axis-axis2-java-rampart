/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements.  See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership.  The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License.  You may obtain a copy of the License at
 * 
 *  http://www.apache.org/licenses/LICENSE-2.0
 * 
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied.  See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */

package org.apache.rampart.policy;

import org.apache.ws.secpolicy.model.Header;
import org.apache.ws.secpolicy.model.SupportingToken;

public class SupportingPolicyData extends RampartPolicyData {

    public void build(SupportingToken token) {

        if (token.getSignedParts() != null && !token.getSignedParts().isOptional()) {
            this.setSignBody(token.getSignedParts().isBody());
            for (Header header : token.getSignedParts().getHeaders()) {
                this.addSignedPart(header.getNamespace(), header.getName());
            }
        }

        if (token.getEncryptedParts() != null && !token.getEncryptedParts().isOptional()) {
            this.setEncryptBody(token.getEncryptedParts().isBody());
            for (Header header : token.getEncryptedParts().getHeaders()) {
                this.setEncryptedParts(header.getNamespace(), header.getName(),
                        "Header");
            }
        }

        if (token.getSignedElements() != null && !token.getSignedElements().isOptional()) {
            for (String xpath : token.getSignedElements().getXPathExpressions()) {
                this.setSignedElements(xpath);
            }
            this.addDeclaredNamespaces(token.getSignedElements()
                    .getDeclaredNamespaces());
        }

        if (token.getEncryptedElements() != null && !token.getEncryptedElements().isOptional()) {
            for (String xpath : token.getEncryptedElements().getXPathExpressions()) {
                this.setEncryptedElements(xpath);
            }
            if (token.getSignedElements() == null) {
                this.addDeclaredNamespaces(token.getEncryptedElements()
                        .getDeclaredNamespaces());
            }
        }
    }
}
