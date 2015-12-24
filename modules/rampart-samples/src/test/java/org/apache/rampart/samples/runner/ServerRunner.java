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

import org.apache.tools.ant.BuildLogger;

final class ServerRunner implements Runnable {
    private final Controller controller;
    private final Sample sample;
    private final BuildLogger logger;
    private final int port;

    ServerRunner(Controller controller, Sample sample, BuildLogger logger, int port) {
        this.controller = controller;
        this.sample = sample;
        this.logger = logger;
        this.port = port;
    }

    public void run() {
        try {
            sample.runServer(logger, port);
        } finally {
            controller.serverStopped();
        }
    }
}
