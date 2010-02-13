/*
 * Copyright 2006 The Apache Software Foundation.
 * Copyright 2006 International Business Machines Corp.
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
package org.apache.axis2.jaxws.core.util;

import org.apache.axis2.AxisFault;
import org.apache.axis2.jaxws.ExceptionFactory;
import org.apache.axis2.jaxws.core.MessageContext;
import org.apache.axis2.util.Utils;

/**
 * A utility class for handling some of the common issues related to 
 * the JAX-WS MessageContext.
 */
public class MessageContextUtils {

    /**
     * Given a MessageContext, create a new MessageContext from there with the
     * necessary information to make sure the new MessageContext is related
     * to the existing one.  An example of a usage for this would be to create
     * the MessageContext for a response based on the MessageContext of a 
     * particular request. 
     * 
     * @param mc - the MessageContext to use as the source
     * @return
     */
    public static MessageContext createMessageMessageContext(MessageContext mc) {
        try {
            org.apache.axis2.context.MessageContext sourceAxisMC = mc.getAxisMessageContext();
            
            // There are a number of things that need to be copied over at the
            // Axis2 level.
            org.apache.axis2.context.MessageContext newAxisMC = 
                Utils.createOutMessageContext(sourceAxisMC);
            
            MessageContext newMC = new MessageContext(newAxisMC);
            
            return newMC;
        } catch (AxisFault e) {
            throw ExceptionFactory.makeWebServiceException(e);
        }
    }
    
}
