package org.apache.rampart;

public class RampartConstants {
		
	public static final String TIME_LOG = "org.apache.rampart.TIME";
	public static final String MESSAGE_LOG = "org.apache.rampart.MESSAGE";
	public static final String SEC_FAULT = "SECURITY_VALIDATION_FAILURE";
        /**
         * The key under which the HTTPS client certificate, determened by the https listener, may
         * be populated as a property of the message context.
         */
        public static final String HTTPS_CLIENT_CERT_KEY = "https.client.cert.key";
    public static final String MERLIN_CRYPTO_IMPL = "org.apache.ws.security.components.crypto.Merlin";
    public static final String MERLIN_CRYPTO_IMPL_CACHE_KEY = "org.apache.ws.security.crypto.merlin.file";

    public static final String XML_ENCRYPTION_MODIFIER_CONTENT = "Content";
    public static final String XML_ENCRYPTION_MODIFIER_ELEMENT = "Element";
}
