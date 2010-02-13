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
package org.apache.axis2.saaj;

import junit.framework.TestCase;

import javax.xml.soap.SOAPConnection;
import javax.xml.soap.SOAPConnectionFactory;
import javax.xml.soap.SOAPException;

/**
 * 
 */
public class SOAPConnectionTest extends TestCase {
    public void testClose() {
        try {
            SOAPConnection sCon = SOAPConnectionFactory.newInstance().createConnection();
            sCon.close();
        } catch (SOAPException e) {
            fail("Unexpected Exception " + e);
        }
    }

    public void testCloseTwice() {
        SOAPConnectionFactory soapConnectionFactory = null;
        try {
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
        } catch (SOAPException e) {
            fail("Unexpected Exception " + e);
        }

        SOAPConnection sCon = null;
        try {
            sCon = soapConnectionFactory.createConnection();
            sCon.close();
        } catch (SOAPException e) {
            fail("Unexpected Exception " + e);
        }

        try {
            sCon.close();
            fail("Expected Exception did not occur");
        } catch (SOAPException e) {
            assertTrue(true);
        }
    }

    public void testCallOnCloseConnection(){
        SOAPConnectionFactory soapConnectionFactory = null;
        try {
            soapConnectionFactory = SOAPConnectionFactory.newInstance();
        } catch (SOAPException e) {
            fail("Unexpected Exception " + e);
        }

        SOAPConnection sCon = null;
        try {
            sCon = soapConnectionFactory.createConnection();
            sCon.close();
        } catch (SOAPException e) {
            fail("Unexpected Exception " + e);
        }

        try {
            sCon.call(null, new Object());
            fail("Expected Exception did not occur");
        } catch (SOAPException e) {
            assertTrue(true);
        }
    }
}
