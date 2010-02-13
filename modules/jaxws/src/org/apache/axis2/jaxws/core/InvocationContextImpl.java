/*
 * Copyright 2006 The Apache Software Foundation.
 * Copyright 2006 International Business Machines Corp.
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
package org.apache.axis2.jaxws.core;

import java.util.List;
import java.util.concurrent.Executor;

import javax.xml.ws.handler.Handler;

import org.apache.axis2.client.ServiceClient;
import org.apache.axis2.jaxws.impl.AsyncListener;

/**
 * An implementation of the InvocationContext interface.
 * 
 * @see org.apache.axis2.jaxws.core.InvocationContext
 */
public class InvocationContextImpl implements InvocationContext {

    private List<Handler> handlers;
    private MessageContext requestMsgCtx;
    private MessageContext responseMsgCtx;
    private Executor executor;
    private AsyncListener asyncListener;
    
    private ServiceClient serviceClient; //FIXME: This is temporary
    
    public InvocationContextImpl() {
        //do nothing
    }
    
    /**
     * @see org.apache.axis2.jaxws.core.InvocationContext#getHandlers()
     */
    public List<Handler> getHandlers() {
        return handlers;
    }
    
    /**
     * Sets the list of hanlders for this InvocationContext
     * 
     * @param list
     */
    public void setHandlers(List<Handler> list) {
        handlers = list;
    }

    /**
     * @see org.apache.axis2.jaxws.core.InvocationContext#setRequestMessageContext(MessageContext)
     */
    public void setRequestMessageContext(MessageContext ctx) {
        requestMsgCtx = ctx;
    }

    /**
     * @see org.apache.axis2.jaxws.core.InvocationContext#setResponseMessageContext(MessageContext)
     */
    public void setResponseMessageContext(MessageContext ctx) {
        responseMsgCtx = ctx;
    }

    /**
     * @see org.apache.axis2.jaxws.core.InvocationContext#getResponseMessageContext()
     */
    public MessageContext getResponseMessageContext() {
        return responseMsgCtx;
    }

    /**
     * @see org.apache.axis2.jaxws.core.InvocationContext#getRequestMessageContext()
     */
    public MessageContext getRequestMessageContext() {
        return requestMsgCtx;
    }
    
    public Executor getExecutor() {
        return executor;
    }
    
    public void setExecutor(Executor e) {
        executor = e;
    }
    
    public AsyncListener getAsyncListener() {
        return asyncListener;
    }
    
    public void setAsyncListener(AsyncListener al) {
        asyncListener = al;
    }
    
    // FIXME: This is temporary
    public ServiceClient getServiceClient() {
        return serviceClient;
    }
    
    // FIXME: This is temporary
    public void setServiceClient(ServiceClient client) {
        serviceClient = client;
    }
}
