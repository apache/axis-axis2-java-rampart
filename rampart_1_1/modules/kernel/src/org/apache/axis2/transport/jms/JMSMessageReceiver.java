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
package org.apache.axis2.transport.jms;

import edu.emory.mathcs.backport.java.util.concurrent.Executor;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.engine.AxisEngine;
import org.apache.axis2.util.UUIDGenerator;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.jms.*;
import javax.naming.Context;
import javax.xml.stream.XMLStreamException;
import java.io.InputStream;

/**
 * This is the actual receiver which listens for and accepts JMS messages, and
 * hands them over to be processed by a worker thread. An instance of this
 * class is created for each JMSConnectionFactory, but all instances may and
 * will share the same worker thread pool.
 */
public class JMSMessageReceiver implements MessageListener {

    private static final Log log = LogFactory.getLog(JMSMessageReceiver.class);

    /** The thread pool of workers */
    private Executor workerPool = null;
    /** The Axis configuration context */
    private ConfigurationContext axisConf = null;
    /** A reference to the JMS Connection Factory */
    private JMSConnectionFactory jmsConFac = null;

    /**
     * Create a new JMSMessage receiver
     * @param jmsConFac the JMS connection factory associated with
     * @param workerPool the worker thead pool to be used
     * @param axisConf the Axis2 configuration
     */
    JMSMessageReceiver(JMSConnectionFactory jmsConFac,
        Executor workerPool, ConfigurationContext axisConf) {
        this.jmsConFac = jmsConFac;
        this.workerPool = workerPool;
        this.axisConf = axisConf;
    }

    /**
     * Return the Axis configuration
     * @return the Axis configuration
     */
    public ConfigurationContext getAxisConf() {
        return axisConf;
    }

    /**
     * Set the worker thread pool
     * @param workerPool the worker thead pool
     */
    public void setWorkerPool(Executor workerPool) {
        this.workerPool = workerPool;
    }

    /**
     * The entry point on the recepit of each JMS message
     * @param message the JMS message received
     */
    public void onMessage(Message message) {
        // directly create a new worker and delegate processing
        try {
            log.debug("Received JMS message to destination : " +
                message.getJMSDestination());
        } catch (JMSException e) {
            e.printStackTrace();
        }
        workerPool.execute(new Worker(message));
    }

    /**
     * Creates an Axis MessageContext for the received JMS message and
     * sets up the transports and various properties
     * @param message the JMS message
     * @return the Axis MessageContext
     */
    private MessageContext createMessageContext(Message message) {

        InputStream in = JMSUtils.getInputStream(message);

        try {
            MessageContext msgContext = new MessageContext();

            // get destination and create correct EPR
            Destination dest = message.getJMSDestination();
            String destinationName = null;
            if (dest instanceof Queue) {
                destinationName = ((Queue) dest).getQueueName();
            } else if (dest instanceof Topic) {
                destinationName = ((Topic) dest).getTopicName();
            }

            String serviceName = jmsConFac.getServiceNameForDestination(destinationName);

            // hack to get around the crazy Active MQ dynamic queue and topic issues
            if (serviceName == null) {
                String provider = (String) jmsConFac.getProperties().get(
                    Context.INITIAL_CONTEXT_FACTORY);
                if (provider.indexOf("activemq") != -1) {
                    serviceName = jmsConFac.getServiceNameForDestination(
                        ((dest instanceof Queue ?
                            JMSConstants.ACTIVEMQ_DYNAMIC_QUEUE :
                            JMSConstants.ACTIVEMQ_DYNAMIC_TOPIC) + destinationName));
                }
            }


            if (serviceName != null) {
                // set to bypass dispatching and handover directly to this service
                msgContext.setAxisService(
                    axisConf.getAxisConfiguration().getService(serviceName));
            }

            msgContext.setConfigurationContext(axisConf);
            msgContext.setIncomingTransportName(Constants.TRANSPORT_JMS);
            msgContext.setTransportIn(
                axisConf.getAxisConfiguration().getTransportIn(JMSConstants.JMS_QNAME));

            msgContext.setTransportOut(
                axisConf.getAxisConfiguration().getTransportOut(JMSConstants.JMS_QNAME));
            // the reply is assumed to be on the JMSReplyTo destination, using
            // the same incoming connection factory
            msgContext.setProperty(Constants.OUT_TRANSPORT_INFO,
                 new JMSOutTransportInfo(jmsConFac.getConFactory(), message.getJMSReplyTo()));

            msgContext.setServerSide(true);
            msgContext.setServiceGroupContextId(UUIDGenerator.getUUID());

            String soapAction = JMSUtils.getProperty(message, JMSConstants.SOAPACTION);
            if (soapAction != null) {
                msgContext.setSoapAction(soapAction);
            }

            msgContext.setEnvelope(
                JMSUtils.getSOAPEnvelope(message, msgContext, in));

            return msgContext;

        } catch (JMSException e) {
            handleException("JMS Exception reading the destination name", e);
        } catch (AxisFault e) {
            handleException("Axis fault creating the MessageContext", e);
        } catch (XMLStreamException e) {
            handleException("Error reading the SOAP envelope", e);
        }
        return null;
    }

    private void handleException(String msg, Exception e) {
        log.error(msg, e);
        throw new AxisJMSException(msg, e);
    }

    /**
     * The actual Runnable Worker implementation which will process the
     * received JMS messages in the worker thread pool
     */
    class Worker implements Runnable {

        private Message message = null;

        Worker(Message message) {
            this.message = message;
        }

        public void run() {
            MessageContext msgCtx = createMessageContext(message);

            AxisEngine engine = new AxisEngine(msgCtx.getConfigurationContext());
            try {
                log.debug("Delegating JMS message for processing to the Axis engine");
                if (msgCtx.getEnvelope().getBody().hasFault()) {
                    engine.receiveFault(msgCtx);
                } else {
                    engine.receive(msgCtx);
                }
            } catch (AxisFault af) {
                log.error("JMS Worker [" + Thread.currentThread().getName() +
                    "] Encountered an Axis Fault : " + af.getMessage(), af);
            }
        }
    }
}
