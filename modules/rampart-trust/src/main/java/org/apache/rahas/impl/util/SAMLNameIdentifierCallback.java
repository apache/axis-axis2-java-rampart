package org.apache.rahas.impl.util;

import org.apache.rahas.RahasData;
import org.opensaml.SAMLNameIdentifier;

public class SAMLNameIdentifierCallback implements SAMLCallback{
	
	private SAMLNameIdentifier nameId = null;
	private String userId = null;
	private RahasData data = null;
	
	public SAMLNameIdentifierCallback(RahasData data){
		this.data = data;
	}
	
	public int getCallbackType(){
		return SAMLCallback.NAME_IDENTIFIER_CALLBACK;
	}

	public SAMLNameIdentifier getNameId() {
		return nameId;
	}

	public void setNameId(SAMLNameIdentifier nameId) {
		this.nameId = nameId;
	}

	public void setUserId(String userId) {
		this.userId = userId;
	}

	public String getUserId() {
		return userId;
	}
		
}
