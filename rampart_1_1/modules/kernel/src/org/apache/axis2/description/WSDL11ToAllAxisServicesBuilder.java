/*
 * Copyright 2004,2005 The Apache Software Foundation.
 *
 * Licensed under the Apache License, Version 2.0 (the "License"); you may not
 * use this file except in compliance with the License. You may obtain a copy of
 * the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations under
 * the License.
 *
 *
 */
package org.apache.axis2.description;

import java.io.InputStream;
import java.util.ArrayList;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.Map.Entry;

import javax.wsdl.Definition;
import javax.wsdl.Port;
import javax.wsdl.Service;
import javax.wsdl.WSDLException;
import javax.xml.namespace.QName;

import org.apache.axis2.AxisFault;
import org.apache.axis2.wsdl.WSDLConstants;
import org.apache.commons.logging.Log;
import org.apache.commons.logging.LogFactory;

/**
 * Extends the WSDL11ToAxisServiceBuilder class to provide functionality to return
 * multiple AxisService objects; one for each port on each service in the WSDL 1.1 file.
 *
 */
public class WSDL11ToAllAxisServicesBuilder extends WSDL11ToAxisServiceBuilder {
    protected static final Log log =
        LogFactory.getLog(WSDL11ToAllAxisServicesBuilder.class);

    public static final String WSDL_SERVICE_QNAME = "WSDL_SERVICE_QNAME";

    public static final String WSDL_PORT = "WSDL_PORT";

    private ArrayList axisServices = null;
    
    /**
     * Class constructor.  
     * @param in  - Contains the wsdl 1.1 file
     */
    public WSDL11ToAllAxisServicesBuilder(InputStream in) {
        super(in);
        axisServices = new ArrayList();   // create an empty ArrayList
    }
    
    /**
     * Public method to access the wsdl 1.1 file and create a List of AxisService objects.
     * For each port on each service in the wsdl, an AxisService object is created and
     * added to the List.  The name of the AxisService is changed from the service name
     * to the port name, since port names are unique to the wsdl.  
     * @return A List containing one AxisService object for each port in the wsdl file.
     * The name of the AxisService is modified from the service name to the port name.
     * @throws AxisFault 
     */
    public List populateAllServices() throws AxisFault {
        try {
            if (log.isDebugEnabled()) {
                log.debug("Entry: populateAllServices");
            }

            setup();  // setup contains code with gathers non-service specific info
                      // from the WSDL.  This only needs to be done once per WSDL.
            if (wsdl4jDefinition == null) {  
                if (log.isDebugEnabled()) {
                    log.debug("Exit: populateAllServices.  wsdl definition is null!");
                }
                return null;   // can't go any further without the wsdl
            }
            Iterator wsdlServIter = wsdl4jDefinition.getServices().entrySet().iterator();

            while (wsdlServIter.hasNext()) {
                Entry entry = (Entry) wsdlServIter.next();
                Service service = (Service) entry.getValue();
                // set the serviceName on the parent to setup call to populateService
                serviceName = service.getQName();
                Iterator wsdlPortIter = service.getPorts().entrySet().iterator();
                while (wsdlPortIter.hasNext()) {
                    Entry portEntry = (Entry) wsdlPortIter.next();
                    Port port = (Port) portEntry.getValue();
                    portName = port.getName();
                    // start with a fresh axisService
                    this.axisService = new AxisService();
                    // now that serviceName and portName are set, call up to the
                    // parent class to populate this service.                   
                    AxisService retAxisService = populateService();
                    if (retAxisService != null) {
                        // save off the wsdl service QName as a parameter.
                        Parameter serviceNameParameter = new Parameter();
                        serviceNameParameter.setName(WSDL_SERVICE_QNAME);
                        serviceNameParameter.setValue(serviceName);
                        retAxisService.addParameter(serviceNameParameter);
                        // Also save off the javax.wsdl.Port object that this AxisService
                        // represents.
                        Parameter portParameter = new Parameter();
                        portParameter.setName(WSDL_PORT);
                        portParameter.setValue(port);
                        retAxisService.addParameter(portParameter);                        
                        // since this AxisService really represents the wsdl
                        // port, change the name
                        // from wsdl service name to port name.
                        retAxisService.setName(portName); // TODO: mangle name????

                        axisServices.add(retAxisService);
                    } // end if axisService was returned
                } // end for all ports of a service
            } // end for all services in the wsdl
            
            if (log.isDebugEnabled()) {
                log.debug("Exit: populateAllServices.");
            }
            return axisServices;
        } catch (AxisFault e) {
            throw e;  // just rethrow any AxisFaults
        } catch (Exception e) {
            if (log.isDebugEnabled()) {
                log.debug("populateAllServices caught Exception.  Converting to AxisFault. " + e.toString());
            }
            throw new AxisFault(e);
        }
    }

}
