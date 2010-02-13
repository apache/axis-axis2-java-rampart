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


package org.apache.axis2.transport.mail;

import edu.emory.mathcs.backport.java.util.concurrent.ExecutorService;
import edu.emory.mathcs.backport.java.util.concurrent.LinkedBlockingQueue;
import edu.emory.mathcs.backport.java.util.concurrent.ThreadPoolExecutor;
import edu.emory.mathcs.backport.java.util.concurrent.TimeUnit;
import org.apache.axiom.om.impl.builder.StAXBuilder;
import org.apache.axiom.om.util.StAXUtils;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.SOAPEnvelope;
import org.apache.axiom.soap.impl.builder.StAXSOAPModelBuilder;
import org.apache.axis2.AxisFault;
import org.apache.axis2.Constants;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.context.ConfigurationContext;
import org.apache.axis2.context.ConfigurationContextFactory;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.description.TransportInDescription;
import org.apache.axis2.description.TransportOutDescription;
import org.apache.axis2.i18n.Messages;
import org.apache.axis2.transport.TransportListener;
import org.apache.axis2.transport.TransportUtils;
import org.apache.axis2.util.threadpool.DefaultThreadFactory;
import org.apache.axis2.util.Utils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

import javax.mail.Flags;
import javax.mail.Message;
import javax.mail.MessagingException;
import javax.mail.URLName;
import javax.mail.internet.MimeMessage;
import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamReader;
import java.io.ByteArrayInputStream;
import java.io.File;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.Properties;

/**
 * This is the implementation for Mail Listener in Axis2. It has the full capability
 * of connecting to a POP3 or IMPA server with SSL or regualar connection. This listener intend
 * to use as a server in client side as well with the involcation is Async with addressing.
 */


public class SimpleMailListener implements Runnable, TransportListener {
    private static final Log log = LogFactory.getLog(SimpleMailListener.class);

    private ConfigurationContext configurationContext = null;

    private boolean running = true;
    /*password and replyTo is Axis2 specific*/
    private String user = "";
    private String replyTo = "";

    /*This hold properties for pop3 or impa server connection*/
    private Properties pop3Properties = new Properties();

    private EmailReceiver receiver = null;

    /**
     * Time has been put from best guest. Let the default be 3 mins.
     * This value is configuralble from Axis2.xml. Under mail transport listener
     * simply set the following parameter.
     * <parameter name="transport.listener.interval ">[custom listener interval]</parameter>
     */
    private int listenerWaitInterval = 1000 * 60 * 3;

    private ExecutorService workerPool;

    private static final int WORKERS_MAX_THREADS = 5;
    private static final long WORKER_KEEP_ALIVE = 60L;
    private static final TimeUnit TIME_UNIT = TimeUnit.SECONDS;

    private LinkedBlockingQueue messageQueue;

    public SimpleMailListener() {
    }

    public void init(ConfigurationContext configurationContext, TransportInDescription transportIn)
            throws AxisFault {
        this.configurationContext = configurationContext;

        ArrayList mailParameters = transportIn.getParameters();

        replyTo = Utils.getParameterValue(
                transportIn.getParameter(org.apache.axis2.transport.mail.Constants.RAPLY_TO));
        Parameter listenerWaitIntervalParam = transportIn
                .getParameter(org.apache.axis2.transport.mail.Constants.LISTENER_INTERVAL);
        if (listenerWaitIntervalParam != null) {
            listenerWaitInterval =
                    Integer.parseInt(Utils.getParameterValue(listenerWaitIntervalParam));
        }

        String password = "";
        String host = "";
        String protocol = "";
        String port = "";
        URLName urlName;

        for (Iterator iterator = mailParameters.iterator(); iterator.hasNext();) {
            Parameter param = (Parameter) iterator.next();
            String paramKey = param.getName();
            String paramValue = Utils.getParameterValue(param);
            if (paramKey == null || paramValue == null) {
                throw new AxisFault(Messages.getMessage("canNotBeNull",
                                                        "Parameter name nor value should be null"));

            }
            pop3Properties.setProperty(paramKey, paramValue);
            if (paramKey.equals(org.apache.axis2.transport.mail.Constants.POP3_USER)) {
                user = paramValue;
            }
            if (paramKey.equals(org.apache.axis2.transport.mail.Constants.POP3_PASSWORD)) {
                password = paramValue;
            }
            if (paramKey.equals(org.apache.axis2.transport.mail.Constants.POP3_HOST)) {
                host = paramValue;
            }
            if (paramKey.equals(org.apache.axis2.transport.mail.Constants.STORE_PROTOCOL)) {
                protocol = paramValue;
            }
            if (paramKey.equals(org.apache.axis2.transport.mail.Constants.POP3_PORT)) {
                port = paramValue;
            }

        }
        if (password.length() == 0 || user.length() == 0 || host.length() == 0 || protocol.length() == 0) {
            throw new AxisFault("One or more of Password, User, Host and Protocol are null or empty");
        }

        if (port.length() == 0) {
            urlName = new URLName(protocol, host, -1, "", user, password);
        } else {
            urlName = new URLName(protocol, host, Integer.parseInt(port), "", user, password);
        }

        receiver = new EmailReceiver();
        receiver.setPop3Properties(pop3Properties);
        receiver.setUrlName(urlName);


    }

    /**
     * Server process.
     */
    public static void main(String args[]) throws AxisFault {
        if (args.length < 2) {
            log.info("java SimpleMailListener <repository>");
            printUsage();
        } else {
            String path = args[0];
            String axis2xml = args[1];
            ConfigurationContext configurationContext;
            File repo = new File(path);
            if (repo.exists()) {
                configurationContext =
                        ConfigurationContextFactory.createConfigurationContextFromFileSystem(path,axis2xml);
            } else {
                printUsage();
                throw new AxisFault("repository not found");
            }
            SimpleMailListener sas = new SimpleMailListener();
            TransportInDescription transportIn =
                    configurationContext.getAxisConfiguration().getTransportIn(
                            new QName(Constants.TRANSPORT_MAIL));
            if (transportIn != null) {
                sas.init(configurationContext, transportIn);
                log.info("Starting the SimpleMailListener with repository "
                         + new File(args[0]).getAbsolutePath());
                sas.start();
            } else {
                log.info(
                        "Startup failed, mail transport not configured, Configure the mail trnasport in the axis2.xml file");
            }
        }
    }

    private static void printUsage() {
        System.out.println("Please provide the repository location and axis2.xml location ");
    }

    /**
     * Accept requests from a given TCP port and send them through the Axis
     * engine for processing.
     */
    public void run() {

        // Accept and process requests from the socket
        if (running) {
            log.info("Mail listner strated to listen to the address " + user);
        }

        while (running) {
            try {
                receiver.connect();

                Message[] msgs = receiver.receiveMessages();

                if ((msgs != null) && (msgs.length > 0)) {
                    log.info(msgs.length + " Message Found");

                    for (int i = 0; i < msgs.length; i++) {
                        MimeMessage msg = (MimeMessage) msgs[i];
                        MessageContext mc = createMessageContextToMailWorker(msg);
                        if (mc != null) {
                            messageQueue.add(mc);
                        }
                        msg.setFlag(Flags.Flag.DELETED, true);
                    }
                }

                receiver.disconnect();

            } catch (Exception e) {
                log.error("Error in SimpleMailListener" + e);
            } finally {
                try {
                    Thread.sleep(listenerWaitInterval);
                } catch (InterruptedException e) {
                    log.warn("Error Encountered " + e);
                }
            }
        }

    }

    private MessageContext createMessageContextToMailWorker(MimeMessage msg) throws Exception {

        MessageContext msgContext = null;
        TransportInDescription transportIn =
                configurationContext.getAxisConfiguration()
                        .getTransportIn(
                                new QName(org.apache.axis2.Constants.TRANSPORT_MAIL));
        TransportOutDescription transportOut =
                configurationContext.getAxisConfiguration()
                        .getTransportOut(
                                new QName(org.apache.axis2.Constants.TRANSPORT_MAIL));
        if ((transportIn != null) && (transportOut != null)) {
            // create Message Context
            msgContext = new MessageContext();
            msgContext.setConfigurationContext(configurationContext);
            msgContext.setTransportIn(transportIn);
            msgContext.setTransportOut(transportOut);
            msgContext.setServerSide(true);
            msgContext.setProperty(org.apache.axis2.transport.mail.Constants.CONTENT_TYPE,
                                   msg.getContentType());

            if (TransportUtils.getCharSetEncoding(msg.getContentType()) != null) {
                msgContext.setProperty(
                        org.apache.axis2.Constants.Configuration.CHARACTER_SET_ENCODING,
                        TransportUtils.getCharSetEncoding(
                                msg.getContentType()));
            } else {
                msgContext.setProperty(
                        org.apache.axis2.Constants.Configuration.CHARACTER_SET_ENCODING,
                        MessageContext.DEFAULT_CHAR_SET_ENCODING);
            }

            msgContext.setIncomingTransportName(org.apache.axis2.Constants.TRANSPORT_MAIL);
            String soapAction = getMailHeader(msg,
                                              org.apache.axis2.transport.mail.Constants.HEADER_SOAP_ACTION);
            msgContext.setSoapAction(soapAction);
            if (msg.getSubject() != null) {
                msgContext.setTo(new EndpointReference(msg.getSubject()));
            }

            // Create the SOAP Message
            // SMTP basically a text protocol, thus, following would be the optimal way to build the
            // SOAP11/12 body from it.
            String message = msg.getContent().toString();
            ByteArrayInputStream bais =
                    new ByteArrayInputStream(message.getBytes());
            XMLStreamReader reader =
                    StAXUtils.createXMLStreamReader(bais);
            String soapNamespaceURI;
            if (msg.getContentType().indexOf(SOAP12Constants.SOAP_12_CONTENT_TYPE)
                > -1) {
                soapNamespaceURI = SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI;
                // set the soapAction if available
                int index = msg.getContentType().indexOf("action");
                if (index > -1) {
                    String transientString = msg.getContentType().substring(index, msg.getContentType().length());
                    int equal = transientString.indexOf("=");
                    int firstSemiColon = transientString.indexOf(";");
                    if (firstSemiColon > -1) {
                        soapAction = transientString.substring(equal + 1, firstSemiColon);
                    } else {
                        soapAction = transientString.substring(equal + 1, transientString.length());
                    }
                    if ((soapAction != null) && soapAction.startsWith("\"")
                        && soapAction.endsWith("\"")) {
                        soapAction = soapAction
                                .substring(1, soapAction.length() - 1);
                    }
                    msgContext.setSoapAction(soapAction);

                }
            } else if (msg.getContentType().indexOf(
                    SOAP11Constants.SOAP_11_CONTENT_TYPE) > -1) {
                soapNamespaceURI = SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI;
            } else {
                log.warn(
                        "MailWorker found a message other than text/xml or application/soap+xml");
                return null;
            }

            StAXBuilder builder = new StAXSOAPModelBuilder(reader, soapNamespaceURI);
            SOAPEnvelope envelope = (SOAPEnvelope) builder.getDocumentElement();
            msgContext.setEnvelope(envelope);
        }
        return msgContext;
    }

    private String getMailHeader(MimeMessage msg, String headerName) throws AxisFault {
        try {
            String values[] = msg.getHeader(headerName);

            if (values != null) {
                return values[0];
            } else {
                return null;
            }
        } catch (MessagingException e) {
            throw new AxisFault(e);
        }
    }

    /**
     * Start this listener
     */
    public void start() throws AxisFault {
        workerPool = new ThreadPoolExecutor(1,
                                            WORKERS_MAX_THREADS, WORKER_KEEP_ALIVE, TIME_UNIT,
                                            new LinkedBlockingQueue(),
                                            new DefaultThreadFactory(
                                                    new ThreadGroup("Mail Worker thread group"),
                                                    "MailWorker"));

        messageQueue = new LinkedBlockingQueue();

        this.configurationContext.getThreadPool().execute(this);

        MailWorkerManager mailWorkerManager = new MailWorkerManager(configurationContext,
                                                                    messageQueue, workerPool,
                                                                    WORKERS_MAX_THREADS);
        mailWorkerManager.start();
    }

    /**
     * Stop this server.
     * <p/>
     */
    public void stop() {
        running = true;
        if (!workerPool.isShutdown()) {
            workerPool.shutdown();
        }
        log.info("Stopping the mail listner");
    }


    public EndpointReference getEPRForService(String serviceName, String ip) throws AxisFault {
        return getEPRsForService(serviceName, ip)[0];
    }

    public EndpointReference[] getEPRsForService(String serviceName, String ip) throws AxisFault {
        return new EndpointReference[]{new EndpointReference(Constants.TRANSPORT_MAIL + ":" +
                                                             replyTo + configurationContext
                .getServiceContextPath() + "/" + serviceName)};
    }

}
