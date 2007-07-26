package org.apache.rahas.impl.util;

import java.util.ArrayList;
import java.util.List;

import org.apache.rahas.RahasData;
import org.opensaml.SAMLAttribute;

public class SAMLAttributeCallback implements SAMLCallback{
	
	private List attributes = null;
	private RahasData data = null;
	
	public SAMLAttributeCallback(RahasData data){
		attributes = new ArrayList();
		this.data = data;
	}
	
	public int getCallbackType(){
		return SAMLCallback.ATTR_CALLBACK;
	}
	
	public void addAttributes(SAMLAttribute attribute){
		attributes.add(attribute);
	}
	
	public SAMLAttribute[] getAttributes(){
		return (SAMLAttribute[])attributes.toArray(new SAMLAttribute[attributes.size()]);
		
	}


}
