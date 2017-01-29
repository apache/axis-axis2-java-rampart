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

import javax.xml.namespace.QName;

import org.apache.axiom.om.OMElement;
import org.apache.ws.security.WSConstants;
import org.apache.ws.security.message.token.Reference;

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

    public void add(Token token) throws TrustException {
               
        if (token != null && !"".equals(token.getId()) && token.getId() != null) {
            
            writeLock.lock();
            
            try {
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

    public void update(Token token) throws TrustException {
             
        if (token != null && token.getId() != null && token.getId().trim().length() != 0) {
    
            writeLock.lock();    
            
            try {
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
        
        String [] tokenIdentifiers = null;
        
        readLock.lock();
        
        Set identifiers = tokens.keySet();
        tokenIdentifiers = (String[]) identifiers.toArray(new String[identifiers.size()]); 
        
        readLock.unlock();
        
        return tokenIdentifiers;
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

    private Token[] getTokens(int[] states) throws TrustException {
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

    private Token[] getTokens(int state) throws TrustException {
        int[] states = new int[]{state};        
        return getTokens(states);
    }

    public Token getToken(String id) throws TrustException {
        readLock.lock();
        
        Token token;
        
        try {

            token = (Token) this.tokens.get(id);
            if(token != null) {
                processTokenExpiry(token);
            }else{
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
