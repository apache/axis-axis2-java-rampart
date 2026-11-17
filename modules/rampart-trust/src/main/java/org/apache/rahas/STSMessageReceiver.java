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

package org.apache.rahas;

import org.apache.axiom.om.OMElement;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.receivers.AbstractInOutMessageReceiver;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.xml.namespace.QName;

public class STSMessageReceiver extends AbstractInOutMessageReceiver {
    
    private static final Log log = LogFactory.getLog(STSMessageReceiver.class);
    
    public void invokeBusinessLogic(MessageContext inMessage,
            MessageContext outMessage) throws AxisFault {

        try {
            Parameter param = inMessage
                    .getParameter(TokenRequestDispatcherConfig.CONFIG_PARAM_KEY);
            Parameter paramFile = inMessage
                    .getParameter(TokenRequestDispatcherConfig.CONFIG_FILE_KEY);
            TokenRequestDispatcherConfig config;
            if (param != null) {
                config = TokenRequestDispatcherConfig.load(param
                        .getParameterElement().getFirstChildWithName(
                                new QName("token-dispatcher-configuration")));
            } else if (paramFile != null) {
                config = TokenRequestDispatcherConfig.load((String) paramFile
                        .getValue());
            } else {
                config = TokenRequestDispatcherConfig.load(
                        (OMElement) inMessage
                                .getProperty(TokenRequestDispatcherConfig.CONFIG_PARAM_KEY));
            }
            // RAMPART-397: a custom issuer may live in the service archive, which only
            // the service class loader can see.
            if (inMessage.getAxisService() != null) {
                config.setClassLoader(inMessage.getAxisService().getClassLoader());
            }
            TokenRequestDispatcher dispatcher = new TokenRequestDispatcher(config);

            SOAPEnvelope responseEnv = dispatcher.handle(inMessage, outMessage);
			outMessage.setEnvelope(responseEnv);
        } catch (TrustException e) {
            e.printStackTrace();
            //Log the exception
            log.error(e);
            throw new AxisFault(e.getFaultString(), e.getFaultCode());
        }
    }


}
