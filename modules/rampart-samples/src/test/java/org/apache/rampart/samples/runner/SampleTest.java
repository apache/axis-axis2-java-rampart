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

import junit.framework.TestCase;
import junit.framework.TestSuite;

public class SampleTest extends TestCase {
    private final Sample sample;
    
    public SampleTest(String group, String id) {
        super(group + "/" + id);
        this.sample = new Sample(group, id);
    }

    @Override
    protected void runTest() throws Throwable {
        new Controller(sample).execute();
    }

    public static TestSuite suite() {
        TestSuite suite = new TestSuite();
        suite.addTest(new SampleTest("policy", "01"));
        suite.addTest(new SampleTest("policy", "02"));
        suite.addTest(new SampleTest("policy", "03"));
        suite.addTest(new SampleTest("policy", "04"));
        // TODO: these are failing
//        suite.addTest(new SampleTest("policy", "05"));
//        suite.addTest(new SampleTest("policy", "06"));
//        suite.addTest(new SampleTest("policy", "07"));
        suite.addTest(new SampleTest("policy", "08"));
        return suite;
    }
}
