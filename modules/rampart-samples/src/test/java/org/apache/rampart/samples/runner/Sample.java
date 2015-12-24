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

import java.io.File;

import org.apache.tools.ant.BuildLogger;
import org.apache.tools.ant.Project;
import org.apache.tools.ant.ProjectHelper;

final class Sample {
    private final File buildFile;
    private final String sampleId;

    Sample(File buildFile, String sampleId) {
        this.buildFile = buildFile;
        this.sampleId = sampleId;
    }

    private void run(BuildLogger logger, int port, String target) {
        Project project = new Project();
        File targetDir = new File("target");
        project.setUserProperty("env.AXIS2_HOME", new File(targetDir, "axis2").getAbsolutePath());
        project.setUserProperty("build.dir", new File(targetDir, "build").getAbsolutePath());
        project.setUserProperty("client.port", String.valueOf(port));
        project.setUserProperty("server.port", String.valueOf(port));
        ProjectHelper.configureProject(project, buildFile);
        project.addBuildListener(logger);
        project.executeTarget(target);
    }
    
    void runServer(BuildLogger logger, int port) {
        run(logger, port, "service." + sampleId);
    }
    
    void runClient(BuildLogger logger, int port) {
        run(logger, port, "client." + sampleId);
    }
}
