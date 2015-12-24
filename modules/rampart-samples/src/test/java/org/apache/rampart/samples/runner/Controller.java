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

import org.apache.axis2.testutils.PortAllocator;
import org.apache.tools.ant.Project;

final class Controller {
    private final Sample sample;
    private boolean serverReady;
    private boolean serverStopped;
    private boolean serverStopDetected;

    Controller(Sample sample) {
        this.sample = sample;
    }

    void execute() throws InterruptedException {
        int port = PortAllocator.allocatePort();
        Logger logger = new Logger();
        logger.setErrorPrintStream(System.err);
        logger.setOutputPrintStream(System.out);
        logger.setMessageOutputLevel(Project.MSG_INFO);
        ServerWatcher serverWatcher = new ServerWatcher(this, port);
        new Thread(serverWatcher).start();
        try {
            Thread serverRunnerThread = new Thread(new ServerRunner(this, sample, logger, port));
            serverRunnerThread.start();
            try {
                synchronized (this) {
                    if (!serverStopped && !serverReady) {
                        wait();
                    } else if (serverStopped) {
                        return;
                    }
                }
                sample.runClient(logger, port);
            } finally {
                logger.shutdown();
                serverRunnerThread.interrupt();
                synchronized (this) {
                    while (!serverStopDetected) {
                        wait();
                    }
                }
            }
        } finally {
            serverWatcher.stop();
        }
    }
    
    synchronized void serverStopped() {
        serverStopped = true;
        notifyAll();
    }

    synchronized void serverReady() {
        serverReady = true;
        notifyAll();
    }
    
    synchronized void serverStopDetected() {
        serverStopDetected = true;
        notifyAll();
    }
}
