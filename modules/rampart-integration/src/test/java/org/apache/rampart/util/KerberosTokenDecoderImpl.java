/**
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

package org.apache.rampart.util;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

import javax.security.auth.Subject;

import org.apache.directory.shared.kerberos.codec.KerberosDecoder;
import org.apache.directory.shared.kerberos.components.EncTicketPart;
import org.apache.ws.security.WSSecurityException;
import org.apache.ws.security.validate.KerberosTokenDecoder;

/**
 * A copy of wss4j 2.0 Kerberos token decoder implementation.
 * 
 * @see org.apache.wss4j.common.kerberos.KerberosTokenDecoderImpl
 * 
 * TODO Once Rampart adopts wss4j 2.0, this class must be removed in favor of wss4j's
 */
public class KerberosTokenDecoderImpl implements KerberosTokenDecoder {
    
    private static final String KERBEROS_OID = "1.2.840.113554.1.2.2";

    private byte[] serviceTicket;
    private Subject subject;

    private boolean decoded = false;
    private EncTicketPart encTicketPart;

    /**
     * Clear all internal information
     */
    public void clear() {
        serviceTicket = null;
        subject = null;
        decoded = false;
        encTicketPart = null;
    }

    /**
     * Set the AP-REQ Kerberos Token
     *
     * @param token the AP-REQ Kerberos Token
     */
    public void setToken(byte[] token) {
        serviceTicket = token;
    }

    /**
     * Set the Subject
     *
     * @param subject the Subject
     */
    public void setSubject(Subject subject) {
        this.subject = subject;
    }

    /**
     * Get the session key from the token
     *
     * @return the session key from the token
     */
    public byte[] getSessionKey() {
        if (!decoded) {
            decodeServiceTicket();
        }
        if (encTicketPart != null && encTicketPart.getKey() != null) {
            return encTicketPart.getKey().getKeyValue();
        }
        return null;
    }

    /**
     * Get the client principal name from the decoded service ticket.
     *
     * @return the client principal name
     */
    public String getClientPrincipalName() {
        if (!decoded) {
            decodeServiceTicket();
        }
        return encTicketPart.getCName().toString();
    }

    // Decode the service ticket.
    private synchronized void decodeServiceTicket() {
        parseServiceTicket(serviceTicket);
        decoded = true;
    }

    // Parses the service ticket (GSS AP-REQ token)
    private void parseServiceTicket(byte[] ticket) {
        try {
            // I didn't find a better way how to parse this Kerberos Message...
            org.bouncycastle.asn1.ASN1InputStream asn1InputStream =
                    new org.bouncycastle.asn1.ASN1InputStream(new ByteArrayInputStream(ticket));
            org.bouncycastle.asn1.DERApplicationSpecific derToken =
                    (org.bouncycastle.asn1.DERApplicationSpecific) asn1InputStream.readObject();
            if (derToken == null || !derToken.isConstructed()) {
                asn1InputStream.close();
                throw new WSSecurityException("invalid kerberos token");
            }
            asn1InputStream.close();

            asn1InputStream = new org.bouncycastle.asn1.ASN1InputStream(new ByteArrayInputStream(derToken.getContents()));
            org.bouncycastle.asn1.DERObjectIdentifier kerberosOid =
                    (org.bouncycastle.asn1.DERObjectIdentifier) asn1InputStream.readObject();
            if (!kerberosOid.getId().equals(KERBEROS_OID)) {
                asn1InputStream.close();
                throw new WSSecurityException("invalid kerberos token");
            }

            int readLowByte = asn1InputStream.read() & 0xff;
            int readHighByte = asn1InputStream.read() & 0xff;
            int read = (readHighByte << 8) + readLowByte; //NOPMD
            if (read != 0x01) {
                throw new WSSecurityException("invalid kerberos token");
            }
            
            this.encTicketPart = KerberosDecoder.decodeEncTicketPart(toByteArray(asn1InputStream));
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    private static byte[] toByteArray(InputStream inputStream) throws IOException {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        int read;
        byte[] buf = new byte[1024];
        while ((read = inputStream.read(buf)) != -1) {
            byteArrayOutputStream.write(buf, 0, read);
        }
        return byteArrayOutputStream.toByteArray();
    }
}
