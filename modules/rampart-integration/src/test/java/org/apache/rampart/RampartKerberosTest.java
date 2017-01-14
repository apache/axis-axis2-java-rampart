package org.apache.rampart;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.net.URL;

import javax.xml.namespace.QName;
import javax.xml.stream.XMLStreamException;

import org.apache.axiom.om.OMElement;
import org.apache.axis2.client.ServiceClient;
import org.apache.commons.io.IOUtils;
import org.apache.neethi.Policy;
import org.apache.rampart.policy.model.KerberosConfig;
import org.apache.rampart.policy.model.RampartConfig;
import org.apache.rampart.util.KerberosServer;
import org.custommonkey.xmlunit.XMLAssert;
import org.xml.sax.SAXException;

/**
 * Tests Kerberos authentication over transport binding using a Kerberos token as supporting endorsing token.
 * The test will use Apache DS Kerberos server, see {@link KerberosServer}.
 * 
 * The test is tailored for Oracle Java execution since it uses <code>com.sun.security.auth.module.Krb5LoginModule</code> JAAS login module for Kerberos authentication.
 */
public class RampartKerberosTest extends AbstractRampartTest {

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
    
    /**
     * Stores any original JAAS configuration set via {@link #JAAS_CONF_SYS_PROP} property to restore it after test execution.
     */
    protected String jaasConf;
    
    /**
     * Stores any original Kerberos 5 configuration set via {@link #KRB5_CONF_SYS_PROP} property to restore it after test execution.
     */
    protected String krb5Conf;
    
    public void testKerberosOverTransportKeytab() throws XMLStreamException, SAXException, IOException {
        final String serviceName = "KerberosOverTransportKeytab";
        URL serviceUrl = new URL(String.format("https://localhost:%s/axis2/services/%s?wsdl", getHttpsPort(), serviceName));
        
        ServiceClient serviceClient = getServiceClientInstance(serviceUrl);

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
        XMLAssert.assertXMLEqual(echoElement.toStringWithConsume(), result.toStringWithConsume());
    }
    
    public void testKerberosOverTransportPWCB() throws XMLStreamException, SAXException, IOException {
        final String serviceName = "KerberosOverTransportPWCB";
        URL serviceUrl = new URL(String.format("https://localhost:%s/axis2/services/%s?wsdl", getHttpsPort(), serviceName));
        
        ServiceClient serviceClient = getServiceClientInstance(serviceUrl);

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
        XMLAssert.assertXMLEqual(echoElement.toStringWithConsume(), result.toStringWithConsume());
    }
    
    
    public void testKerberosDelegation() throws XMLStreamException, SAXException, IOException {
        final String serviceName = "KerberosDelegation";
        URL serviceUrl = new URL(String.format("https://localhost:%s/axis2/services/%s?wsdl", getHttpsPort(), serviceName));

        ServiceClient serviceClient = getServiceClientInstance(serviceUrl);

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
        XMLAssert.assertXMLEqual(echoElement.toStringWithConsume(), result.toStringWithConsume());
    }
    
    /* (non-Javadoc)
     * @see org.apache.rampart.AbstractRampartTest#setUp()
     */
    @Override
    protected void setUp() throws Exception {
        super.setUp();
        
        System.setProperty("sun.security.krb5.debug", "true");
        System.setProperty("sun.security.jgss.debug", "true");
        
        KerberosServer.startKerberosServer();
                        
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

    /* (non-Javadoc)
     * @see org.apache.rampart.AbstractRampartTest#tearDown()
     */
    @Override
    protected void tearDown() throws Exception {
        super.tearDown();
        
        KerberosServer.stopKerberosServer();
        
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
    		
		krb5ConfContent = krb5ConfContent.replace(KERBEROS_CONF_KDC_PORT_TOKEN, String.valueOf(KerberosServer.getPort()));
    	
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

	/* (non-Javadoc)
	 * @see org.apache.rampart.AbstractRampartTest#isEnableHttp()
	 */
	@Override
	protected boolean isEnableHttp() {
		//Kerberos test does not use http
		return false;
	}

	/* (non-Javadoc)
	 * @see org.apache.rampart.AbstractRampartTest#isEnableHttps()
	 */
	@Override
	protected boolean isEnableHttps() {
		return true;
	}
}
