/*
 * Copyright 2004,2005 The Apache Software Foundation.
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
package org.apache.axis2.jaxws;

import javax.xml.ws.AsyncHandler;
import javax.xml.ws.Response;

import test.EchoStringResponse;

public class JAXBCallbackHandler<T> implements AsyncHandler<T> {

    public void handleResponse(Response response) {
        try {
            EchoStringResponse esr = (EchoStringResponse) response.get();
            System.out.println(">> Async response received: " + esr.getEchoStringReturn());
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
