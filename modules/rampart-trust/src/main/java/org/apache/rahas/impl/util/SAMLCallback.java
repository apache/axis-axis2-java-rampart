package org.apache.rahas.impl.util;

public interface SAMLCallback {
	
	/**
	 * Attribute callback
	 */
	public static final int ATTR_CALLBACK = 1;
	
	/**
	 * Subject name identifier
	 */
	public static final int NAME_IDENTIFIER_CALLBACK = 2;
	
	int getCallbackType();

}
