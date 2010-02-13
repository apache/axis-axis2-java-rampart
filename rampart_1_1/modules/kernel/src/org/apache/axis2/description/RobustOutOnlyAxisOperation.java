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

package org.apache.axis2.description;

import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.SOAPFault;
import org.apache.axis2.AxisFault;
import org.apache.axis2.client.OperationClient;
import org.apache.axis2.client.Options;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.context.ServiceContext;
import org.apache.axis2.engine.AxisEngine;
import org.apache.axis2.transport.TransportUtils;
import org.apache.axis2.wsdl.WSDLConstants;

import javax.xml.namespace.QName;
import java.io.InputStream;

public class RobustOutOnlyAxisOperation extends OutInAxisOperation {
    public RobustOutOnlyAxisOperation() {
        super();
        setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_ROBUST_OUT_ONLY);
    }

    public RobustOutOnlyAxisOperation(QName name) {
        super(name);
        setMessageExchangePattern(WSDL20_2004Constants.MEP_URI_ROBUST_OUT_ONLY);
    }

    public OperationClient createClient(ServiceContext sc, Options options) {
        return new RobustOperationClient(this, sc, options);
    }

    class RobustOperationClient extends OutInAxisOperationClient {

        public RobustOperationClient(OutInAxisOperation axisOp, ServiceContext sc, Options options) {
            super(axisOp, sc, options);
        }

        protected MessageContext send(MessageContext msgctx) throws AxisFault {
            AxisEngine engine = new AxisEngine(msgctx.getConfigurationContext());

            // create the responseMessageContext
            MessageContext responseMessageContext = new MessageContext();

            // This is a hack - Needs to change
            responseMessageContext.setOptions(options);


            responseMessageContext.setServerSide(false);
            responseMessageContext.setMessageID(msgctx.getMessageID());
            addMessageContext(responseMessageContext);
            responseMessageContext.setServiceContext(msgctx.getServiceContext());
            responseMessageContext.setAxisMessage(
                    msgctx.getAxisOperation().getMessage(WSDLConstants.MESSAGE_LABEL_IN_VALUE));

            //sending the message
            engine.send(msgctx);
            responseMessageContext.setDoingREST(msgctx.isDoingREST());

            responseMessageContext.setProperty(MessageContext.TRANSPORT_IN, msgctx
                    .getProperty(MessageContext.TRANSPORT_IN));
            responseMessageContext.setTransportIn(msgctx.getTransportIn());
            responseMessageContext.setTransportOut(msgctx.getTransportOut());

            // Options object reused above so soapAction needs to be removed so
            // that soapAction+wsa:Action on response don't conflict
            responseMessageContext.setSoapAction("");

            SOAPEnvelope envelope = responseMessageContext.getEnvelope();
            if (envelope == null) {
                // If request is REST we assume the responseMessageContext is REST, so
                // set the variable
                InputStream inStream = (InputStream) responseMessageContext.
                        getProperty(MessageContext.TRANSPORT_IN);
                if (inStream != null) {
                    envelope = TransportUtils.createSOAPMessage(
                            responseMessageContext, msgctx.getEnvelope().getNamespace()
                            .getNamespaceURI());
                }
            }
            if (envelope != null) {
                if (envelope.getBody().hasFault()) {
                    //receiving a fault
                    engine.receiveFault(responseMessageContext);
                    SOAPFault soapFault = envelope.getBody().getFault();
                    throw new AxisFault(soapFault.getCode(), soapFault.getReason(),
                            soapFault.getNode(), soapFault.getRole(), soapFault.getDetail());
                }
            }
            return null;
        }
    }
}
