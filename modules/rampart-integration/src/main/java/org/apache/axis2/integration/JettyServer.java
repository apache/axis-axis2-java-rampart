/*
 * Copyright 2004 - 2014 The Apache Software Foundation.
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
package org.apache.axis2.integration;

import java.io.File;

import org.eclipse.jetty.server.Connector;
import org.eclipse.jetty.server.Server;
import org.eclipse.jetty.server.nio.SelectChannelConnector;
import org.eclipse.jetty.server.ssl.SslSelectChannelConnector;
import org.eclipse.jetty.servlet.ServletHolder;
import org.eclipse.jetty.util.ssl.SslContextFactory;
import org.eclipse.jetty.webapp.WebAppContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.axis2.testutils.PortAllocator;
import org.apache.axis2.transport.http.AxisServlet;

/**
 * Support for running an embedded Jetty server
 */
public class JettyServer {

    /**
     * Keystore to configure for Jetty's ssl context factory: {@value}
     */
    public static final String KEYSTORE = "target/test-resources/jetty/server.jks";
    
    /**
     * Keymanager password to configure for Jetty's ssl context factory: {@value
     */
    public static final String KEYMAN_PASSWORD = "password";
    
    /**
     * Keystore password to configure for Jetty's ssl context factory: {@value} 
     */
    public static final String KEYSTORE_PASSWORD = "password";
    
    /**
     * The alias of the certificate to configure for Jetty's ssl context factory: {@value}
     */
    public static final String CERT_ALIAS = "server";
    
    /**
     * Client keystore containing Jetty's server certificate as trusted certificate entry: : {@value}
     */
    public static final String CLIENT_KEYSTORE = "target/test-resources/jetty/client.jks";
                    
    /**
     * Axis2 configuration file to use: {@value}
     */
    public static final String AXIS2_XML = "src/test/resources/conf/axis2.xml";
    
    /**
     * Webapp resource base directory to use: {@value}
     */
    public static final String WEBAPP_DIR = "target" + File.separator + "webapp";
    
    private static final Logger logger = LoggerFactory.getLogger(JettyServer.class);
    
    private static Server server;
    
    private JettyServer() {
        
    }
    
    /**
     * Starts the embedded Jetty server using dynamic port allocation with both http and https connectors enabled.
     * 
     * @param repository The path to the Axis2 repository to use. Must not be null or empty.
     * 
     * @throws Exception
     */
    public static synchronized void start(String repository) throws Exception {
        start(repository, true, true);
    }
    
    /**
     * Starts the embedded Jetty server using dynamic port allocation.
     * 
     * @param repository The path to the Axis2 repository to use. Must not be null or empty.
     * @param enableHttp Specifies whether to enable http connector.
     * @param enableHttps Specifies whether to enable https connector.
     * 
     * @throws Exception
     */
    public static synchronized void start(String repository, boolean enableHttp, boolean enableHttps) throws Exception {
        int httpPort = enableHttp ? PortAllocator.allocatePort() : -1;
        int httpsPort = enableHttps ? PortAllocator.allocatePort() : -1;
        
        start(repository, httpPort, httpsPort);
    }
    
    /**
     * Starts the embedded Jetty server.
     * 
     * @param repository The path to the Axis2 repository to use. Must not be null or empty.
     * @param httpPort The http port to use. Set to <code>-1</code> to disable http connector.
     * @param httpsPort The https port to use. Set to <code>-1</code> to disable https connector.
     * 
     * @throws Exception
     * @throws IllegalArgumentException If both ports are set to <code>-1</code>
     */
    public static synchronized void start(String repository, int httpPort, int httpsPort) throws Exception {
        if (repository == null || repository.trim().length() == 0) {
            throw new IllegalArgumentException("Axis2 repository must not be null or empty");
        }
        else if (httpPort == -1 && httpsPort == -1) {
            throw new IllegalArgumentException("At least one port must be specified.");
        }
    
        server = new Server();
        
        SelectChannelConnector connector = null;
        if (httpPort == -1) {
            logger.debug("Http connector is disabled");
        }
        else {
            logger.info("Starting http connector on port: " + httpPort);
            
            connector = new SelectChannelConnector();
            connector.setPort(httpPort);
            server.addConnector(connector);
        }
        
        if (httpsPort == -1) {
            logger.debug("Https connector is disabled");
        }
        else {
            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStorePath(KEYSTORE);
            sslContextFactory.setKeyStorePassword(KEYSTORE_PASSWORD);
            sslContextFactory.setKeyManagerPassword(KEYMAN_PASSWORD);
            sslContextFactory.setTrustStore(KEYSTORE);
            sslContextFactory.setTrustStorePassword(KEYSTORE_PASSWORD);
            sslContextFactory.setCertAlias(CERT_ALIAS);
            SslSelectChannelConnector sslConnector = new SslSelectChannelConnector(sslContextFactory);
            
            logger.info("Starting https connector on port: " + httpsPort);
            
            sslConnector.setPort(httpsPort);
            server.addConnector(sslConnector);
            
            if (connector != null) {
                connector.setConfidentialPort(httpsPort);
            }
        }
        
        WebAppContext context = new WebAppContext();
        File webappDir = new File(WEBAPP_DIR);
        if (!webappDir.exists() && !webappDir.mkdirs()) {
            logger.error("Failed to create Axis2 webapp directory: " + webappDir.getAbsolutePath());
        }
        
        context.setResourceBase(webappDir.getAbsolutePath());
        context.setContextPath("/axis2");
        context.setParentLoaderPriority(true);
        context.setThrowUnavailableOnStartupException(true);
        
        ServletHolder servlet = new ServletHolder();
        servlet.setClassName(AxisServlet.class.getName());
        servlet.setInitParameter("axis2.repository.path", repository);
        servlet.setInitParameter("axis2.xml.path", AXIS2_XML);
        
        //load on startup to trigger Axis2 initialization and service deployment
        //this is for backward compatibility with the SimpleHttpServer which initializes Axis2 on startup
        servlet.setInitOrder(0);
        
        context.addServlet(servlet, "/services/*");
        
        server.setHandler(context);
        
        try {
            server.start();
        }
        catch (SecurityException e) {
            if (e.getMessage().equals("class \"javax.servlet.ServletRequestListener\"'s signer information does not match signer information of other classes in the same package")) {
                logger.error(
                 "It is likely your test classpath contains multiple different versions of servlet api.\n" +
                 "If you are running this test in an IDE, please configure it to exclude Rampart's core module servlet api dependency.");
                throw e;
            }
        }
    }
    
    /**
     * Stops the embedded Jetty server.
     * 
     * @throws Exception
     */
    public static synchronized void stop() throws Exception {
        if (server != null) {
            logger.info("Stop called");
            server.stop();
            server = null;
        }
    }

    /**
     * @return Jetty's http connector port. 
     * @throws IllegalStateException If Jetty is not running or the http connector cannot be found.
     */
    public static synchronized int getHttpPort() throws IllegalStateException {
        assertStarted();
        
        Connector[] connectors = server.getConnectors();
        if (connectors.length == 0) {
            throw new IllegalStateException("Jetty server is not configured with any connectors");
        }
        
        for (Connector connector : connectors) {
            if ((connector instanceof SelectChannelConnector) &&
                !(connector instanceof SslSelectChannelConnector)) {
                //must be the http connector
                return connector.getPort();
            }
        }
        
        throw new IllegalStateException("Could not find Jetty http connector");
    }
    
    /**
     * @return Jetty's ssl connector port. 
     * @throws IllegalStateException If Jetty is not running or the ssl connector cannot be found.
     */
    public static synchronized int getHttpsPort() throws IllegalStateException {
        assertStarted();
        
        Connector[] connectors = server.getConnectors();
        if (connectors.length == 0) {
            throw new IllegalStateException("Jetty server is not configured with any connectors");
        }
        
        for (Connector connector : connectors) {
            if (connector instanceof SslSelectChannelConnector) {
                //must be the https connector
                return connector.getPort();
            }
        }
        
        throw new IllegalStateException("Could not find Jetty https connector");
    }
    
    private static void assertStarted() throws IllegalStateException {
        if (server == null) {
            throw new IllegalStateException("Jetty server is not initialized");
        }
        else if (!server.isStarted()) {
            throw new IllegalStateException("Jetty server is not started");
        }
    }
}
