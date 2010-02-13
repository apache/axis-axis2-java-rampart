/*
 * Copyright 2006 The Apache Software Foundation.
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
package org.apache.axis2.addressing.wsdl;

import java.util.List;

import javax.wsdl.Definition;
import javax.wsdl.Fault;
import javax.wsdl.Input;
import javax.wsdl.Operation;
import javax.wsdl.Output;
import javax.wsdl.PortType;
import javax.wsdl.extensions.AttributeExtensible;
import javax.xml.namespace.QName;

import org.apache.axis2.addressing.AddressingConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * The WSDL11ActionHelper provides 3 static methods to determine the correct wsa:Action value from
 * a wsdl4j Input/Output/Fault object. It first attempts to access the wsaw:Action attribute and if
 * that is not found uses the WSDL11DefaultActionPatternHelper to generate and Action based on the
 * Default Action Pattern for WSDL1.1 at http://www.w3.org/TR/2006/WD-ws-addr-wsdl-20060216/#defactionwsdl11
 */
public class WSDL11ActionHelper {
	
	private static final Log log = LogFactory.getLog(WSDL11ActionHelper.class);
	
	/**
	 * getActionFromInputElement
	 * @param def the wsdl:definitions which contains the wsdl:portType
	 * @param wsdl4jPortType the wsdl:portType which contains the wsdl:operation
	 * @param op the wsdl:operation which contains the input element
	 * @param input the input element to be examined to generate the wsa:Action
	 * @return either the wsaw:Action from the input element or an action generated using the DefaultActionPattern
	 */
    public static String getActionFromInputElement(Definition def, PortType wsdl4jPortType, Operation op, Input input){
        String result = getWSAWActionExtensionAttribute(input);
        if(result == null){
            result = WSDL11DefaultActionPatternHelper.generateActionFromInputElement(def, wsdl4jPortType, op, input);
        }
        log.trace(result);
    	return result;
    }
    
    /**
	 * getActionFromOutputElement
	 * @param def the wsdl:definitions which contains the wsdl:portType
	 * @param wsdl4jPortType the wsdl:portType which contains the wsdl:operation
	 * @param op the wsdl:operation which contains the output element
	 * @param output the input element to be examined to generate the wsa:Action
	 * @return either the wsaw:Action from the output element or an action generated using the DefaultActionPattern
	 */
    public static String getActionFromOutputElement(Definition def, PortType wsdl4jPortType, Operation op, Output output){
    	String result = getWSAWActionExtensionAttribute(output);
    	if(result == null){
    		result = WSDL11DefaultActionPatternHelper.generateActionFromOutputElement(def, wsdl4jPortType, op, output);
        }
    	log.trace(result);
    	return result;
    }
    
    /**
	 * getActionFromFaultElement
	 * @param def the wsdl:definitions which contains the wsdl:portType
	 * @param wsdl4jPortType the wsdl:portType which contains the wsdl:operation
	 * @param op the wsdl:operation which contains the fault element
	 * @param fault the fault element to be examined to generate the wsa:Action
	 * @return either the wsaw:Action from the fault element or an action generated using the DefaultActionPattern
	 */
    public static String getActionFromFaultElement(Definition def, PortType wsdl4jPortType, Operation op, Fault fault){
    	String result = getWSAWActionExtensionAttribute(fault);
    	if(result == null){
    		result = WSDL11DefaultActionPatternHelper.generateActionFromFaultElement(def, wsdl4jPortType, op, fault);
        }
    	log.trace(result);
    	return result;
    }

    private static String getWSAWActionExtensionAttribute(AttributeExtensible ae){
    	// Search first for a wsaw:Action using the submission namespace
    	Object attribute = ae.getExtensionAttribute(new QName(AddressingConstants.Submission.WSA_NAMESPACE, AddressingConstants.WSA_ACTION));
    	// Then if that did no exist one using the w3c namespace
    	if(attribute ==null){
    		attribute = ae.getExtensionAttribute(new QName(AddressingConstants.Final.WSAW_NAMESPACE, AddressingConstants.WSA_ACTION));
        }
    	
    	// wsdl4j may return a String, QName or a List of either
    	// If it is a list, extract the first element
    	if(attribute instanceof List){
    		List l = (List)attribute;
    		if(l.size()>0){
    			attribute = l.get(0);
    		}else{
    			attribute = null;
    		}
    	}
    	
    	// attribute must now be a QName or String or null
    	// If it is a QName, take the LocalPart as a String
    	if(attribute instanceof QName){
    		QName qn = (QName)attribute;
    		attribute = qn.getLocalPart();
    	}
    	
    	if(!(attribute instanceof String)){
    		if(log.isTraceEnabled()){
    			log.trace("No wsaw:Action attribute found");
    		}
    		return null;
    	}else{
    		String result = (String)attribute;
    		log.trace(result);
    		return result;
    	}
    }
}
