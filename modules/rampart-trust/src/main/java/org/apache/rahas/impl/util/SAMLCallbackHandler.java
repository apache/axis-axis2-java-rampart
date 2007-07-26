package org.apache.rahas.impl.util;

import org.opensaml.SAMLException;

public interface SAMLCallbackHandler {

	public void handle(SAMLCallback callback) throws SAMLException;

}
