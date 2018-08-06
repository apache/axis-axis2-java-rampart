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
package org.apache.rampart.testutils;

import java.security.cert.CertificateExpiredException;
import java.security.cert.CertificateNotYetValidException;
import java.security.cert.X509Certificate;
import java.util.Calendar;
import java.util.Date;

import org.aspectj.lang.annotation.Around;
import org.aspectj.lang.annotation.Aspect;

/**
 * Aspect that redirects {@link X509Certificate#checkValidity()} to
 * {@link X509Certificate#checkValidity(Date)} with a fixed date. This allows
 * executing unit tests relying on certificates that have expired.
 */
@Aspect
public class FakeValidationDateAspect {
    private final static Date VALIDATION_DATE;

    static {
        Calendar cal = Calendar.getInstance();
        cal.setTimeInMillis(0);
        cal.set(2018, 0, 1);
        VALIDATION_DATE = cal.getTime();
    }

    @Around("call(void java.security.cert.X509Certificate.checkValidity()) && target(cert)")
    public void aroundCheckValidity(X509Certificate cert) throws CertificateExpiredException, CertificateNotYetValidException {
        cert.checkValidity(VALIDATION_DATE);
    }
}
