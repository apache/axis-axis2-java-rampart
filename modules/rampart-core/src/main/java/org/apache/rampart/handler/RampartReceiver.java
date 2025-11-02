/*
 * Copyright 2004,2005 The Apache Software Foundation.
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

package org.apache.rampart.handler;

import org.apache.axiom.om.OMException;
import org.apache.axiom.soap.SOAP11Constants;
import org.apache.axiom.soap.SOAP12Constants;
import org.apache.axiom.soap.SOAPHeader;
import org.apache.axiom.soap.SOAPHeaderBlock;
import org.apache.axis2.AxisFault;
import org.apache.axis2.context.MessageContext;
import org.apache.axis2.description.HandlerDescription;
import org.apache.axis2.description.Parameter;
import org.apache.axis2.engine.Handler;
import org.apache.axis2.namespace.Constants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;
import org.apache.rampart.RampartConstants;
import org.apache.rampart.RampartEngine;
import org.apache.rampart.RampartException;
import org.apache.ws.secpolicy.WSSPolicyException;
import org.apache.wss4j.common.ext.WSSecurityException;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.dom.engine.WSSecurityEngineResult;
import org.apache.wss4j.dom.handler.WSHandlerConstants;
import org.apache.wss4j.dom.handler.WSHandlerResult;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.Iterator;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;

import javax.xml.namespace.QName;

/**
 * Rampart inflow handler.
 * This processes the incoming message and validates it against the effective 
 * policy.
 */
public class RampartReceiver implements Handler {
	
    private static Log mlog = LogFactory.getLog(RampartConstants.MESSAGE_LOG);
	
    private static HandlerDescription EMPTY_HANDLER_METADATA =
        new HandlerDescription("default Handler");

    private HandlerDescription handlerDesc;
    
    public RampartReceiver() {
        this.handlerDesc = EMPTY_HANDLER_METADATA;
    }
    
    public void cleanup() {        
    }

    public void init(HandlerDescription handlerdesc) {
        this.handlerDesc = handlerdesc;
    }

    public void flowComplete(MessageContext msgContext)
    {
    	
    }

    public InvocationResponse invoke(MessageContext msgContext) throws AxisFault {

        if (mlog.isDebugEnabled()) {
            String timestamp = java.time.LocalDateTime.now().format(java.time.format.DateTimeFormatter.ofPattern("yyyy-MM-dd HH:mm:ss.SSS"));
            mlog.debug("=== RAMPARTRECEIVER: Processing incoming request ===");
            mlog.debug("RampartReceiver TIMESTAMP: " + timestamp);
            mlog.debug("RampartReceiver: Action = " + (msgContext.getOptions() != null ? msgContext.getOptions().getAction() : "null"));
            mlog.debug("RampartReceiver: To = " + (msgContext.getOptions() != null ? msgContext.getOptions().getTo() : "null"));
        }

        if (!msgContext.isEngaged(WSSHandlerConstants.SECURITY_MODULE_NAME)) {
            if (mlog.isDebugEnabled()) {
                mlog.debug("RampartReceiver: Security module not engaged, continuing");
            }
            return InvocationResponse.CONTINUE;
        }
        
        if(mlog.isDebugEnabled()){
        	mlog.debug("*********************** RampartReceiver received \n"
                    + msgContext.getEnvelope());
        }
        
        if(mlog.isDebugEnabled()){
            mlog.debug("RampartReceiver: Processing incoming message");
            mlog.debug("RampartReceiver: Action = " + msgContext.getOptions().getAction());
            mlog.debug("RampartReceiver: To = " + msgContext.getOptions().getTo());
            mlog.debug("RampartReceiver: Message flow = " + (msgContext.getFLOW() == MessageContext.IN_FLOW ? "IN_FLOW" :
                                                                     msgContext.getFLOW() == MessageContext.OUT_FLOW ? "OUT_FLOW" :
                                                                     msgContext.getFLOW() == MessageContext.IN_FAULT_FLOW ? "IN_FAULT_FLOW" :
                                                                     msgContext.getFLOW() == MessageContext.OUT_FAULT_FLOW ? "OUT_FAULT_FLOW" : "UNKNOWN"));
            try {
                mlog.debug("RampartReceiver: Incoming envelope:");
                mlog.debug(msgContext.getEnvelope().toString());
            } catch (Exception e) {
                mlog.debug("RampartReceiver: Could not log envelope: " + e.getMessage());
            }
        }

        RampartEngine engine = new RampartEngine();
        List<WSSecurityEngineResult> wsResult = null;
        try {
            if(mlog.isDebugEnabled()){
                mlog.debug("RampartReceiver: About to call RampartEngine.process()");
            }
            wsResult = engine.process(msgContext);
            if(mlog.isDebugEnabled()){
                mlog.debug("RampartReceiver: RampartEngine.process() completed successfully");
            }
            
        } catch (WSSecurityException e) {
            if(mlog.isDebugEnabled()){
                mlog.debug("RampartReceiver: WSSecurityException in RampartEngine.process(): " + e.getMessage());
                e.printStackTrace();
            }
            setFaultCodeAndThrowAxisFault(msgContext, e);
        } catch (WSSPolicyException e) {
            if(mlog.isDebugEnabled()){
                mlog.debug("RampartReceiver: WSSPolicyException in RampartEngine.process(): " + e.getMessage());
                e.printStackTrace();
            }
            setFaultCodeAndThrowAxisFault(msgContext, e);
        } catch (RampartException e) {
            if(mlog.isDebugEnabled()){
                mlog.debug("RampartReceiver: RampartException in RampartEngine.process(): " + e.getMessage());
                e.printStackTrace();
            }
            setFaultCodeAndThrowAxisFault(msgContext, e);
        } 
        
        if(wsResult == null) {
          return InvocationResponse.CONTINUE;        
        }
        
        List<WSHandlerResult> results = null;
        if ((results = (List<WSHandlerResult>) msgContext
                .getProperty(WSHandlerConstants.RECV_RESULTS)) == null) {
            results = new ArrayList<WSHandlerResult>();
            msgContext.setProperty(WSHandlerConstants.RECV_RESULTS, results);
        }
        WSHandlerResult rResult = new WSHandlerResult("", wsResult, filterActionResults(wsResult));
        results.add(0, rResult);
        
        SOAPHeader header = null;
        try {
            header = msgContext.getEnvelope().getHeader();
        } catch (OMException ex) {
            throw new AxisFault(
                    "RampartReceiver: cannot get SOAP header after security processing",
                    ex);
        }

        Iterator headers = header.getChildElements();

        SOAPHeaderBlock headerBlock = null;

        while (headers.hasNext()) { // Find the wsse header
            SOAPHeaderBlock hb = (SOAPHeaderBlock) headers.next();
            if (hb.getLocalName().equals(WSConstants.WSSE_LN)
                    && hb.getNamespace().getNamespaceURI().equals(WSConstants.WSSE_NS)) {
                headerBlock = hb;
                break;
            }
        }

        if(headerBlock != null) {
            headerBlock.setProcessed();
        }
        
        return InvocationResponse.CONTINUE;        

    }
    
    private  Map<Integer, List<WSSecurityEngineResult>> filterActionResults( List<WSSecurityEngineResult> results) {
    	Map<Integer, List<WSSecurityEngineResult>> actionResultsMap = new HashMap();
    	
        for (WSSecurityEngineResult result : results) {
            Integer resultTag = (Integer)result.get(WSSecurityEngineResult.TAG_ACTION);
            if (null != resultTag) {
            	List<WSSecurityEngineResult> actionResults = actionResultsMap.get(resultTag);
            	if (null == actionResults) {
            		actionResults = new ArrayList<>();
            		actionResultsMap.put(resultTag, actionResults);
            	}
            	actionResults.add(result);
            }
        }
    	return actionResultsMap;
    }
    
    public HandlerDescription getHandlerDesc() {
        return this.handlerDesc;
    }

    public String getName() {
        return "Apache Rampart inflow handler";
    }

    public Parameter getParameter(String name) {
        return this.handlerDesc.getParameter(name);
    }
    
    private void setFaultCodeAndThrowAxisFault(MessageContext msgContext, Exception e) throws AxisFault {
        
        msgContext.setProperty(RampartConstants.SEC_FAULT, Boolean.TRUE);    
        String soapVersionURI =  msgContext.getEnvelope().getNamespace().getNamespaceURI();
        QName faultCode = null;
        /*
         * Get the faultCode from the thrown WSSecurity exception, if there is one
         */
        if (e instanceof WSSecurityException)
        {        	
        	faultCode = ((WSSecurityException)e).getFaultCode(); 
        }
        /*
         * Otherwise default to InvalidSecurity
         */
        if (faultCode == null)
        {
        	faultCode = new QName(WSConstants.INVALID_SECURITY.getNamespaceURI(),WSConstants.INVALID_SECURITY.getLocalPart(),"wsse");
        }
        
        if (soapVersionURI.equals(SOAP11Constants.SOAP_ENVELOPE_NAMESPACE_URI) ) {
            
            throw new AxisFault(faultCode,e.getMessage(),e);
                            
        } else if (soapVersionURI.equals(SOAP12Constants.SOAP_ENVELOPE_NAMESPACE_URI)) {
            
            List subfaultCodes = new ArrayList();
            subfaultCodes.add(faultCode);
            throw new AxisFault(Constants.FAULT_SOAP12_SENDER,subfaultCodes,e.getMessage(),e);
        
        }        
        
    }

}
