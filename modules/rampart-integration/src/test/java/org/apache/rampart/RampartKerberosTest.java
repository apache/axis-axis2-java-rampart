package org.apache.rampart;

import static com.google.common.truth.Truth.assertAbout;
import static org.apache.axiom.truth.xml.XMLTruth.xml;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMAbstractFactory;
import org.apache.axiom.om.OMElement;
import org.apache.axiom.om.OMFactory;
import org.apache.axiom.om.OMNamespace;
import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.testutils.ClientHelper;
import org.apache.axis2.testutils.JettyServer;
import org.apache.axis2.transport.http.HTTPConstants;
import org.apache.commons.io.IOUtils;
import org.apache.neethi.Policy;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.rampart.util.KerberosServer;
import org.junit.After;
import org.junit.Before;
import org.junit.ClassRule;
import org.junit.Test;

/**
 * Tests Kerberos authentication over transport binding using a Kerberos token as supporting endorsing token.
 * The test will use Apache DS Kerberos server, see {@link KerberosServer}.
 * 
 * The test is tailored for Oracle Java execution since it uses <code>com.sun.security.auth.module.Krb5LoginModule</code> JAAS login module for Kerberos authentication.
 */
public class RampartKerberosTest {

    /**
     * Java system property for setting JAAS configuration file: {@value}
     */
    public static final String JAAS_CONF_SYS_PROP = "java.security.auth.login.config";
    
    /**
     * Java system property for setting Kerberos 5 configuration file: {@value}
     */
    public static final String KRB5_CONF_SYS_PROP = "java.security.krb5.conf";
    
    /**
     * JAAS configuration file to use: {@value}
     * <p>
     * Contains Kerberos login module entries for authenticating client and server principals:
     * </p>
     */
    public static final String KERBEROS_JAAS_CONF = "src/test/resources/kerberos/jaas.conf";
    
    /**
     * Kerberos configuration file <b>template</b> to use: {@value}
     * <p>
     * Specifies the Kerberos realm and KDC server to use, the configuration must contain a <code>KDC_PORT</code> literal
     * which will be replaced with actual KDC server port.
     * </p>
     */
    public static final String KERBEROS_CONF_TEMPLATE = "src/test/resources/kerberos/krb5.conf.template";
    
    /**
     * A token literal in kerberos5 configuration file template that must be replaced with actual KDC port value: {@value}
     */
    public static final String KERBEROS_CONF_KDC_PORT_TOKEN = "KDC_PORT";
    
    @ClassRule
    public static final JettyServer server = new JettyServer("target/test-resources/rampart_service_repo", true);
    
    @ClassRule
    public static final ClientHelper clientHelper = new ClientHelper(server, "target/test-resources/rampart_client_repo") {
        @Override
        protected void configureServiceClient(ServiceClient serviceClient) throws Exception {
            int timeout = 200000;
            serviceClient.getOptions().setTimeOutInMilliSeconds(timeout);
            serviceClient.getOptions().setProperty(HTTPConstants.SO_TIMEOUT, timeout);
            serviceClient.getOptions().setProperty(HTTPConstants.CONNECTION_TIMEOUT, timeout);

            serviceClient.engageModule("addressing");
            serviceClient.engageModule("rampart");
        }
    };
    
    @ClassRule
    public static final KerberosServer kerberosServer = new KerberosServer();
    
    /**
     * Stores any original JAAS configuration set via {@link #JAAS_CONF_SYS_PROP} property to restore it after test execution.
     */
    protected String jaasConf;
    
    /**
     * Stores any original Kerberos 5 configuration set via {@link #KRB5_CONF_SYS_PROP} property to restore it after test execution.
     */
    protected String krb5Conf;
    
    private static OMElement getEchoElement() {
        OMFactory fac = OMAbstractFactory.getOMFactory();
        OMNamespace omNs = fac.createOMNamespace(
                "http://example1.org/example1", "example1");
        OMElement method = fac.createOMElement("echo", omNs);
        OMElement value = fac.createOMElement("Text", omNs);
        value.addChild(fac.createOMText(value, "Testing Rampart with WS-SecPolicy"));
        method.addChild(value);

        return method;
    }

    @Test
    public void testKerberosOverTransportKeytab() throws Exception {
        final String serviceName = "KerberosOverTransportKeytab";
        
        ServiceClient serviceClient = clientHelper.createServiceClient(serviceName, null, null);

        System.out.println("Testing WS-Sec: Kerberos scenario: " + serviceName);
                
        
        RampartConfig rampartConfig = new RampartConfig();
        KerberosConfig kerberosConfig = new KerberosConfig();
        rampartConfig.setKerberosConfig(kerberosConfig);

        kerberosConfig.setJaasContext(serviceName + "Client");        

        Policy policy = new Policy();
        policy.addAssertion(rampartConfig);                
        serviceClient.getAxisService().getPolicySubject().attachPolicyComponent(policy);
        
        //Blocking invocation
        QName operation = new QName("http://rampart.apache.org", "echo");
        OMElement echoElement = getEchoElement();
        OMElement result = serviceClient.sendReceive(operation, echoElement);
        assertAbout(xml()).that(result).ignoringNamespaceDeclarations().hasSameContentAs(echoElement);
    }
    
    @Test
    public void testKerberosOverTransportPWCB() throws Exception {
        final String serviceName = "KerberosOverTransportPWCB";
        
        ServiceClient serviceClient = clientHelper.createServiceClient(serviceName, null, null);

        System.out.println("Testing WS-Sec: Kerberos scenario: " + serviceName);

        RampartConfig rampartConfig = new RampartConfig();
        rampartConfig.setUser("alice");        
        rampartConfig.setPwCbClass(org.apache.rahas.PWCallback.class.getName());
        
        KerberosConfig kerberosConfig = new KerberosConfig();
        rampartConfig.setKerberosConfig(kerberosConfig);

        kerberosConfig.setJaasContext(serviceName + "Client");

        Policy policy = new Policy();
        policy.addAssertion(rampartConfig);        
        serviceClient.getAxisService().getPolicySubject().attachPolicyComponent(policy);
        
        //Blocking invocation
        QName operation = new QName("http://rampart.apache.org", "echo");
        OMElement echoElement = getEchoElement();
        OMElement result = serviceClient.sendReceive(operation, echoElement);
        assertAbout(xml()).that(result).ignoringNamespaceDeclarations().hasSameContentAs(echoElement);
    }
    
    @Test
    public void testKerberosDelegation() throws Exception {
        final String serviceName = "KerberosDelegation";

        ServiceClient serviceClient = clientHelper.createServiceClient(serviceName, null, null);

        System.out.println("Testing WS-Sec: Kerberos scenario: " + serviceName);
                
        
        RampartConfig rampartConfig = new RampartConfig();
        KerberosConfig kerberosConfig = new KerberosConfig();
        rampartConfig.setKerberosConfig(kerberosConfig);

        kerberosConfig.setJaasContext(serviceName + "Client");  
        kerberosConfig.setRequstCredentialDelegation(true);

        Policy policy = new Policy();
        policy.addAssertion(rampartConfig);                
        serviceClient.getAxisService().getPolicySubject().attachPolicyComponent(policy);
        
        //Blocking invocation
        QName operation = new QName("http://rampart.apache.org", "echo");
        OMElement echoElement = getEchoElement();
        OMElement result = serviceClient.sendReceive(operation, echoElement);
        assertAbout(xml()).that(result).ignoringNamespaceDeclarations().hasSameContentAs(echoElement);
    }
    
    @Before
    public void setUp() throws Exception {
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");
        
        //configure JGSS
        krb5Conf = System.getProperty(KRB5_CONF_SYS_PROP);
        
        File krb5ConfFile = generateKerberosConf();
        System.out.println("Using Kerberos configuration file: " + krb5ConfFile.getAbsolutePath());
        System.setProperty(KRB5_CONF_SYS_PROP, krb5ConfFile.getAbsolutePath());
        
        //configure JAAS
        jaasConf = System.getProperty(JAAS_CONF_SYS_PROP);
        System.out.println("Using Kerberos JAAS configuration file: " + new File(KERBEROS_JAAS_CONF).getAbsolutePath());
        System.setProperty(JAAS_CONF_SYS_PROP, KERBEROS_JAAS_CONF);
    }

    @After
    public void tearDown() throws Exception {
        if (jaasConf != null) {
            System.setProperty(JAAS_CONF_SYS_PROP, jaasConf);
        }
        else {
            System.clearProperty(JAAS_CONF_SYS_PROP);
        }
        
        if (krb5Conf != null) {
            System.setProperty(KRB5_CONF_SYS_PROP, krb5Conf);
        }
        else {
            System.clearProperty(KRB5_CONF_SYS_PROP);
        }
    }
    
    /**
     * Generates a Kerberos configuration file (krb5.conf) out of the {@link #KERBEROS_CONF_TEMPLATE} file,
     * replacing the {@link #KERBEROS_CONF_KDC_PORT_TOKEN} with actual KDC port.
     * 
     * @return The generated Kerberos configuration file. It will be generated under the following path:
     * <code>target/tmp/{thisClassSimpleName}_krb5.conf</code>
     * 
     * @throws IOException 
     */
    protected File generateKerberosConf() throws IOException {
        File tmpDir = new File("target" + File.separator + "tmp");
        if (!tmpDir.exists() && !tmpDir.mkdirs()) {
            throw new RuntimeException("Failed to create temp directory: " + tmpDir.getAbsolutePath());
        }
        
        File krb5ConfTemplate = new File(KERBEROS_CONF_TEMPLATE);
        if (!krb5ConfTemplate.exists()) {
            throw new IllegalArgumentException("Cannot find kerberos configuration file template: " + krb5ConfTemplate.getAbsolutePath());
        }
        
        FileInputStream krb5ConfTemplateIn = null;
        String krb5ConfContent;
        try {
            krb5ConfTemplateIn = new FileInputStream(krb5ConfTemplate);
            krb5ConfContent = IOUtils.toString(krb5ConfTemplateIn);
        }
        finally {
            IOUtils.closeQuietly(krb5ConfTemplateIn);
        }
        
        if (krb5ConfContent.indexOf(KERBEROS_CONF_KDC_PORT_TOKEN) == -1) {
            throw new IllegalArgumentException(String.format("Cannot find any %s token in kerberos configuration file template: %s",
                    KERBEROS_CONF_KDC_PORT_TOKEN, krb5ConfTemplate.getAbsolutePath()));
        }
            
        krb5ConfContent = krb5ConfContent.replace(KERBEROS_CONF_KDC_PORT_TOKEN, String.valueOf(kerberosServer.getPort()));
        
        File krb5Conf = new File(tmpDir, this.getClass().getSimpleName() + "_krb5.conf");
        FileOutputStream krb5ConfOut = null;
        try {
            krb5ConfOut = new FileOutputStream(krb5Conf);
            IOUtils.write(krb5ConfContent, krb5ConfOut);
        }
        finally {
            IOUtils.closeQuietly(krb5ConfOut);
        }
        
        return krb5Conf;
    }
}
