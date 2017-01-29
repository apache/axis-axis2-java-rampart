/*
 * Licensed to the Apache Software Foundation (ASF) under one
 * or more contributor license agreements. See the NOTICE file
 * distributed with this work for additional information
 * regarding copyright ownership. The ASF licenses this file
 * to you under the Apache License, Version 2.0 (the
 * "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing,
 * software distributed under the License is distributed on an
 * "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY
 * KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations
 * under the License.
 */
package org.apache.rampart.samples.runner;

import java.io.IOException;
import java.io.InputStream;
import java.net.ConnectException;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;

final class ServerWatcher implements Runnable {
    private final Controller controller;
    private final URL url;
    private boolean serverWasReady;
    private boolean stopped;
    
    ServerWatcher(Controller controller, int port) {
        this.controller = controller;
        try {
            url = new URL("http", "localhost", port, "/axis2/services/");
        } catch (MalformedURLException ex) {
            throw new Error("Unexpected exception", ex);
        }
    }
    
    public synchronized void run() {
        while (true) {
            if (stopped) {
                return;
            }
            try {
                HttpURLConnection connection = (HttpURLConnection)url.openConnection();
                int responseCode = connection.getResponseCode();
                InputStream in = connection.getInputStream();
                try {
                    byte[] buffer = new byte[1024];
                    while (in.read(buffer) != -1) {
                        // Just loop;
                    }
                } finally {
                    in.close();
                }
                if (responseCode == 200) {
                    if (!serverWasReady) {
                        serverWasReady = true;
                        controller.serverReady();
                    }
                }
            } catch (ConnectException ex) {
                if (serverWasReady) {
                    controller.serverStopDetected();
                    return;
                }
            } catch (IOException ex) {
                // Just continue trying
            }
            try {
                wait(100);
            } catch (InterruptedException ex) {
                return;
            }
        }
    }

    public synchronized void stop() {
        stopped = true;
        notifyAll();
    }
}
