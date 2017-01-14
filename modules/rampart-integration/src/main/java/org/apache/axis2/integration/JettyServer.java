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
import org.junit.rules.ExternalResource;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.apache.axis2.addressing.EndpointReference;
import org.apache.axis2.transport.http.AxisServlet;

/**
 * Support for running an embedded Jetty server
 */
public class JettyServer extends ExternalResource {

    /**
     * Keystore to configure for Jetty's ssl context factory: {@value}
     */
    private static final String KEYSTORE = "target/test-resources/jetty/server.jks";
    
    /**
     * Keymanager password to configure for Jetty's ssl context factory: {@value
     */
    private static final String KEYMAN_PASSWORD = "password";
    
    /**
     * Keystore password to configure for Jetty's ssl context factory: {@value} 
     */
    private static final String KEYSTORE_PASSWORD = "password";
    
    /**
     * The alias of the certificate to configure for Jetty's ssl context factory: {@value}
     */
    private static final String CERT_ALIAS = "server";
    
    /**
     * Client keystore containing Jetty's server certificate as trusted certificate entry: : {@value}
     */
    private static final String CLIENT_KEYSTORE = "target/test-resources/jetty/client.jks";
                    
    /**
     * Axis2 configuration file to use: {@value}
     */
    private static final String AXIS2_XML = "src/test/resources/conf/axis2.xml";
    
    /**
     * Webapp resource base directory to use: {@value}
     */
    private static final String WEBAPP_DIR = "target" + File.separator + "webapp";
    
    private static final Logger logger = LoggerFactory.getLogger(JettyServer.class);
    
    private final String repository;
    private final int port;
    private final boolean secure;
    private Server server;
    private boolean systemPropertiesSet;
    private String savedTrustStore;
    private String savedTrustStorePassword;
    private String savedTrustStoreType;
    
    /**
     * Constructor.
     * 
     * @param repository
     *            The path to the Axis2 repository to use. Must not be null or empty.
     * @param port
     *            The port to use. Set to <code>0</code> to enable dynamic port allocation.
     * @param secure
     *            Whether to enable HTTPS.
     */
    public JettyServer(String repository, int port, boolean secure) {
        if (repository == null || repository.trim().length() == 0) {
            throw new IllegalArgumentException("Axis2 repository must not be null or empty");
        }
        this.repository = repository;
        this.port = port;
        this.secure = secure;
    }
    
    @Override
    protected void before() throws Throwable {
        server = new Server();
        
        if (!secure) {
            SelectChannelConnector connector = new SelectChannelConnector();
            connector.setPort(port);
            server.addConnector(connector);
        } else {
            SslContextFactory sslContextFactory = new SslContextFactory();
            sslContextFactory.setKeyStorePath(KEYSTORE);
            sslContextFactory.setKeyStorePassword(KEYSTORE_PASSWORD);
            sslContextFactory.setKeyManagerPassword(KEYMAN_PASSWORD);
            sslContextFactory.setTrustStore(KEYSTORE);
            sslContextFactory.setTrustStorePassword(KEYSTORE_PASSWORD);
            sslContextFactory.setCertAlias(CERT_ALIAS);
            SslSelectChannelConnector sslConnector = new SslSelectChannelConnector(sslContextFactory);
            
            sslConnector.setPort(port);
            server.addConnector(sslConnector);
            
            savedTrustStore = System.getProperty("javax.net.ssl.trustStore");
            System.setProperty("javax.net.ssl.trustStore", CLIENT_KEYSTORE);
            savedTrustStorePassword = System.getProperty("javax.net.ssl.trustStorePassword");
            System.setProperty("javax.net.ssl.trustStorePassword", KEYSTORE_PASSWORD);
            savedTrustStoreType = System.getProperty("javax.net.ssl.trustStoreType");
            System.setProperty("javax.net.ssl.trustStoreType", "JKS");
            systemPropertiesSet = true;
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
        
        logger.info("Server started on port " + getPort());
    }
    
    @Override
    protected void after() {
        if (server != null) {
            logger.info("Stop called");
            try {
                server.stop();
            } catch (Exception ex) {
                logger.error("Failed to stop Jetty server", ex);
            }
            server = null;
        }
        if (systemPropertiesSet) {
            if (savedTrustStore != null) {
                System.setProperty("javax.net.ssl.trustStore", savedTrustStore);
            } else {
                System.clearProperty("javax.net.ssl.trustStore");
            }
            if (savedTrustStorePassword != null) {
                System.setProperty("javax.net.ssl.trustStorePassword", savedTrustStorePassword);    
            } else {
                System.clearProperty("javax.net.ssl.trustStorePassword");
            }
            if (savedTrustStoreType != null) {
                System.setProperty("javax.net.ssl.trustStoreType", savedTrustStoreType);
            } else {
                System.clearProperty("javax.net.ssl.trustStoreType");
            }
            savedTrustStore = null;
            savedTrustStorePassword = null;
            savedTrustStoreType = null;
            systemPropertiesSet = false;
        }
    }

    /**
     * @return Jetty's http connector port. 
     * @throws IllegalStateException If Jetty is not running or the http connector cannot be found.
     */
    public int getPort() throws IllegalStateException {
        if (server == null) {
            throw new IllegalStateException("Jetty server is not initialized");
        }
        if (!server.isStarted()) {
            throw new IllegalStateException("Jetty server is not started");
        }
        
        Connector[] connectors = server.getConnectors();
        if (connectors.length == 0) {
            throw new IllegalStateException("Jetty server is not configured with any connectors");
        }
        
        for (Connector connector : connectors) {
            if (connector instanceof SelectChannelConnector) {
                //must be the http connector
                return connector.getLocalPort();
            }
        }
        
        throw new IllegalStateException("Could not find Jetty http connector");
    }

    public String getEndpoint(String serviceName) {
        return String.format("%s://localhost:%s/axis2/services/%s", secure ? "https" : "http", getPort(), serviceName);
    }

    public EndpointReference getEndpointReference(String serviceName) {
        return new EndpointReference(getEndpoint(serviceName));
    }
}
