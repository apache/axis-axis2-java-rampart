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

package org.apache.rahas;

import org.apache.axiom.om.OMElement;
import org.apache.wss4j.dom.WSConstants;
import org.apache.wss4j.common.token.Reference;

import javax.xml.namespace.QName;

import java.io.Serializable;
import java.util.ArrayList;
import java.util.Hashtable;
import java.util.Iterator;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.locks.Lock;
import java.util.concurrent.locks.ReadWriteLock;
import java.util.concurrent.locks.ReentrantReadWriteLock;

/**
 * In-memory implementation of the token storage
 */
public class SimpleTokenStore implements TokenStorage, Serializable {

    protected Map tokens = new Hashtable();
    
    /**
     * We use a read write lock to improve concurrency while avoiding concurrent modification 
     * exceptions.  We allow concurrent reads and avoid concurrent reads and modifications
     * ReentrantReadWriteLock supports a maximum of 65535 recursive write locks and 65535 read locks
     */
     protected final ReadWriteLock readWriteLock = new ReentrantReadWriteLock();
     
     protected final Lock readLock = readWriteLock.readLock();

     protected final Lock writeLock = readWriteLock.writeLock();

    /**
     * Default grace period (5 minutes) after a token's expiry before it becomes
     * eligible for removal from the store.
     */
    public static final long DEFAULT_EXPIRED_TOKEN_GRACE_PERIOD_MILLIS = 5 * 60 * 1000L;

    /**
     * Tokens whose expiry time elapsed more than this many milliseconds ago are
     * purged from the store when a new token is added, so that expired tokens do
     * not accumulate indefinitely and exhaust the heap (RAMPART-337).
     * <p>
     * The grace period deliberately keeps recently-expired tokens around for a
     * while: removing a token the instant it expires can break an in-flight
     * message that still references it, which previously surfaced as
     * "The signature or decryption was invalid (Unsupported key identification)".
     */
    private long expiredTokenGracePeriodMillis = DEFAULT_EXPIRED_TOKEN_GRACE_PERIOD_MILLIS;

    public void add(Token token) throws TrustException {

        if (token != null && !"".equals(token.getId()) && token.getId() != null) {

            writeLock.lock();

            try {
                // Opportunistically retire long-expired tokens so the store does
                // not grow without bound (RAMPART-337).
                removeExpiredTokens();
                if (this.tokens.keySet().size() == 0
                    || (this.tokens.keySet().size() > 0 && !this.tokens
                        .keySet().contains(token.getId()))) {
                    tokens.put(token.getId(), token);
                } else {
                    throw new TrustException("tokenAlreadyExists",
                                            new String[]{token.getId()});
                }
            } finally {
                writeLock.unlock();
            }
        }
    }

    /**
     * Removes tokens whose expiry time elapsed more than
     * {@link #getExpiredTokenGracePeriodMillis()} milliseconds ago. Tokens with
     * no expiry time are never removed. Callers must hold the write lock.
     */
    private void removeExpiredTokens() {
        long now = System.currentTimeMillis();
        for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
            Token token = (Token) iterator.next();
            if (token.getExpires() != null
                && token.getExpires().getTime() + expiredTokenGracePeriodMillis < now) {
                iterator.remove();
            }
        }
    }

    /**
     * The grace period, in milliseconds, applied after a token's expiry before it
     * is eligible for removal from the store.
     */
    public long getExpiredTokenGracePeriodMillis() {
        return expiredTokenGracePeriodMillis;
    }

    /**
     * Sets the grace period, in milliseconds, applied after a token's expiry
     * before it is eligible for removal from the store.
     */
    public void setExpiredTokenGracePeriodMillis(long expiredTokenGracePeriodMillis) {
        this.expiredTokenGracePeriodMillis = expiredTokenGracePeriodMillis;
    }

    public void update(Token token) throws TrustException {
             
        if (token != null && token.getId() != null && token.getId().trim().length() != 0) {
    
            writeLock.lock();

            try {
                // Retire long-expired tokens on update as well as add, so the
                // store is bounded even under update/renew-heavy workloads (RAMPART-337).
                removeExpiredTokens();
                if (!this.tokens.keySet().contains(token.getId())) {
                    throw new TrustException("noTokenToUpdate", new String[]{token.getId()});
                }
                this.tokens.put(token.getId(), token);
            } finally {
                writeLock.unlock();
            }
        } 
        
    }

    public String[] getTokenIdentifiers() throws TrustException {       
        readLock.lock();
        try {
            Set identifiers = tokens.keySet();
            return (String[]) identifiers.toArray(new String[identifiers.size()]);
        } finally {
            readLock.unlock();
        }
    }

    public Token[] getValidTokens() throws TrustException {
        return getTokens(new int[]{Token.ISSUED, Token.RENEWED});
    }

    public Token[] getRenewedTokens() throws TrustException {
        return getTokens(Token.RENEWED);
    }


    public Token[] getCancelledTokens() throws TrustException {
        return getTokens(Token.CANCELLED);
    }

    public Token[] getExpiredTokens() throws TrustException {
        return getTokens(Token.EXPIRED);
    }

    private Token[] getTokens(int... states) throws TrustException {
        List tokens = new ArrayList();
        
        readLock.lock();
        
        try {
            for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
                Token token = (Token) iterator.next();
                processTokenExpiry(token);
                for (int i = 0; i < states.length; i++) {
                    if (token.getState() == states[i]) {
                        tokens.add(token);
                        break;
                    }
                }
            }
        } finally {
            readLock.unlock();
        }
        return (Token[]) tokens.toArray(new Token[tokens.size()]);
    }

    public Token getToken(String id) throws TrustException {
        readLock.lock();
        
        Token token;
        
        try {
            
            token = (Token) this.tokens.get(id);
            
            if(token == null) {
                //Try to find the token using attached refs & unattached refs
                for (Iterator iterator = this.tokens.values().iterator(); iterator.hasNext();) {
                    Token tempToken = (Token) iterator.next();
                    processTokenExpiry(tempToken);
                    OMElement elem = tempToken.getAttachedReference();
                    if(elem != null && id.equals(this.getIdFromSTR(elem))) {
                        token = tempToken;
                    }
                    elem = tempToken.getUnattachedReference();
                    if(elem != null && id.equals(this.getIdFromSTR(elem))) {
                        token = tempToken;
                    }
                    
                }
            } else {
                processTokenExpiry(token);
            }
        
        } finally {
            readLock.unlock();
        }        
        return token;
    }

    public void removeToken(String id){

        writeLock.lock();

        try {
            this.tokens.remove(id);
        } finally {
            writeLock.unlock();
        }        
    }
    
    protected void processTokenExpiry(Token token) throws TrustException {
        if (token.getExpires() != null &&
            token.getExpires().getTime() < System.currentTimeMillis()) {
            token.setState(Token.EXPIRED);
        }
    }
    
    public static String getIdFromSTR(OMElement str) {
        //ASSUMPTION:SecurityTokenReference/KeyIdentifier
        OMElement child = str.getFirstElement();
        if(child == null) {
            return null;
        }
        
        if (child.getQName().equals(new QName(WSConstants.SIG_NS, "KeyInfo"))) {
            return child.getText();
        } else if(child.getQName().equals(Reference.TOKEN)) {
            String uri = child.getAttributeValue(new QName("URI"));
            if (uri.charAt(0) == '#') {
                uri = uri.substring(1);
            }
            return uri;
        } else {
            return null;
        }
    }
    
}
