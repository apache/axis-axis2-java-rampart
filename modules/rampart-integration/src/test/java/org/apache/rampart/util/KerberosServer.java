/**
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
package org.apache.rampart.util;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.net.DatagramSocket;
import java.nio.file.Files;
import java.security.Provider;
import java.security.Security;
import java.util.List;

import org.apache.axis2.testutils.PortAllocator;
import org.apache.commons.io.FileUtils;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.directory.api.ldap.model.entry.DefaultEntry;
import org.apache.directory.api.ldap.model.ldif.LdifEntry;
import org.apache.directory.api.ldap.model.ldif.LdifReader;
import org.apache.directory.server.core.api.DirectoryService;
import org.apache.directory.server.core.api.interceptor.Interceptor;
import org.apache.directory.server.core.api.partition.Partition;
import org.apache.directory.server.core.factory.DefaultDirectoryServiceFactory;
import org.apache.directory.server.core.factory.DirectoryServiceFactory;
import org.apache.directory.server.core.factory.PartitionFactory;
import org.apache.directory.server.core.kerberos.KeyDerivationInterceptor;
import org.apache.directory.server.kerberos.KerberosConfig;
import org.apache.directory.server.kerberos.kdc.KdcServer;
import org.apache.directory.server.protocol.shared.transport.Transport;
import org.apache.directory.server.protocol.shared.transport.UdpTransport;
import org.apache.directory.shared.kerberos.codec.types.EncryptionType;

/**
 * Runs an Apache DS Kerberos server.
 * @see org.apache.wss4j.integration.test.common.KerberosServiceStarter
 */
public class KerberosServer {

    private static final Log log = LogFactory.getLog(KerberosServer.class);
    
    /**
     * The used DirectoryService instance
     */
    private static DirectoryService directoryService;

    /**
     * The used KdcServer instance
     */
    private static KdcServer kdcServer;

    private static Provider provider = null;
    private static int providerPos = 2;
    
    private static File workDir = null;
    
    /**
     * Starts an Apache DS Kerberos server with dynamically allocated port.
     * 
     * @return
     * @throws Exception
     */
    public static synchronized void startKerberosServer() throws Exception {
        int kdcPort = PortAllocator.allocatePort();
        
        DatagramSocket datagramSocket = new DatagramSocket(kdcPort);
        datagramSocket.setReuseAddress(true);
        datagramSocket.close();

        //Ok, apache ds doesn't like the bouncy castle provider at position 2
        //Caused by: KrbException: Integrity check on decrypted field failed (31) - Integrity check on decrypted field failed
        Provider[] installedProviders = Security.getProviders();
        for (int i = 0; i < installedProviders.length; i++) {
            Provider installedProvider = installedProviders[i];
            if ("BC".equals(installedProvider.getName())) {
                provider = installedProvider;
                providerPos = i;
                Security.removeProvider("BC");
                break;
            }
        }
        if (provider != null) {
            Security.addProvider(provider);
        }
        
        workDir = Files.createTempDirectory("server-work").toFile();
        
        DirectoryServiceFactory directoryServiceFactory = new DefaultDirectoryServiceFactory();
        directoryService = directoryServiceFactory.getDirectoryService();
        directoryService.setAccessControlEnabled(false);
        directoryService.setAllowAnonymousAccess(false);
        directoryService.getChangeLog().setEnabled(true);
        
        List<Interceptor> interceptors = directoryService.getInterceptors();
        interceptors.add(new KeyDerivationInterceptor());
        directoryService.setInterceptors(interceptors);
        directoryServiceFactory.init("defaultDS");

        PartitionFactory partitionFactory = directoryServiceFactory.getPartitionFactory();
        Partition partition = partitionFactory.createPartition(directoryService.getSchemaManager(),
            directoryService.getDnFactory(), "example", "dc=example,dc=com", 1000, workDir);

        partitionFactory.addIndex(partition, "objectClass", 1000);
        partitionFactory.addIndex(partition, "dc", 1000);
        partitionFactory.addIndex(partition, "ou", 1000);

        partition.setSchemaManager(directoryService.getSchemaManager());
        // Inject the partition into the DirectoryService
        directoryService.addPartition(partition);

        InputStream is = KerberosServer.class.getClassLoader().getResourceAsStream("kerberos/users.ldif");
        LdifReader ldifReader = new LdifReader(is);
        for (LdifEntry entry : ldifReader) {
            directoryService.getAdminSession().add(new DefaultEntry(directoryService.getSchemaManager(), entry.getEntry()));
        }
        ldifReader.close();

        KerberosConfig kerberosConfig = new KerberosConfig();
        kerberosConfig.setServicePrincipal("krbtgt/EXAMPLE.COM@EXAMPLE.COM");
        kerberosConfig.setPrimaryRealm("EXAMPLE.COM");
        kerberosConfig.setSearchBaseDn("dc=example,dc=com");
        kerberosConfig.setMaximumTicketLifetime(60000 * 1440);
        kerberosConfig.setMaximumRenewableLifetime(60000 * 10080);
        kerberosConfig.setEncryptionTypes(new EncryptionType[]{EncryptionType.AES128_CTS_HMAC_SHA1_96});
        
        kdcServer = new KdcServer(kerberosConfig);
        kdcServer.setServiceName("DefaultKrbServer");        
        
        final String kdcHostname = "localhost";
        log.info(String.format("Starting service on %s:%s", kdcHostname, kdcPort));
        
        UdpTransport udp = new UdpTransport(kdcHostname, kdcPort);
        kdcServer.addTransports(udp);
        kdcServer.setDirectoryService(directoryService);
        kdcServer.start();
    }

    /**
     * @return The Apache DS Kerberos server port.
     * @throws IllegalArgumentException If server or respective transport are not initialized
     */
    public static synchronized int getPort() throws IllegalArgumentException {
        if (kdcServer == null) {
            throw new IllegalStateException("Kerberos server is not initialized");
        }

        Transport[] transports =  kdcServer.getTransports();
        if (transports == null || transports.length == 0) {
            throw new IllegalStateException("Kerberos server does not configure any transports");
        }
        
        for (Transport transport : transports) {
            if (transport instanceof UdpTransport) {
                return transport.getPort();
            }
        }
        
        throw new IllegalStateException(
                String.format("Cannot identify Kerberos server port. List of transports does not contain an %s instance",
                        UdpTransport.class.getName()));
    } 
    
    /**
     * Stops the Apache DS Kerberos server.
     * @throws Exception
     */
    public static synchronized void stopKerberosServer() throws Exception {
        log.info("Stop called");
        try {        
            if (directoryService != null) {
                try {
                    directoryService.shutdown();
                }
                finally {                    
                    try {
                        FileUtils.deleteDirectory(workDir);
                    }
                    catch (IOException e) {
                        log.error("Failed to delete Apache DS working directory: " + workDir.getAbsolutePath() , e);
                    }
                }
                directoryService = null;
            }
        }
        finally {
            if (kdcServer != null) {
                kdcServer.stop();
                kdcServer = null;
            }
            
            if (provider != null) {
                //restore BC position
                Security.removeProvider("BC");
                Security.insertProviderAt(provider, providerPos);
            }
        }
    }
}
