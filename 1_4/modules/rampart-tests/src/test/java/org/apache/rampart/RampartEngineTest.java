/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.rampart;

import org.apache.axis2.context.MessageContext;
import org.apache.neethi.Policy;

public class RampartEngineTest extends MessageBuilderTestBase {


    public RampartEngineTest(String name) {
        super(name);
    }
    
    public void testEmptySOAPMessage() throws Exception {
        
       try {
           MessageContext ctx = getMsgCtx();
           
           String policyXml = "test-resources/policy/rampart-asymm-binding-6-3des-r15.xml";
           Policy policy = this.loadPolicy(policyXml);
           
           ctx.setProperty(RampartMessageData.KEY_RAMPART_POLICY, policy);
           
           RampartEngine engine = new RampartEngine();
           engine.process(ctx);
        } catch (RampartException e) {
           assertEquals(
                    "Expected rampart to complain about missing security header",
                    "Missing wsse:Security header in request", e.getMessage()); 
        }
    }

}
