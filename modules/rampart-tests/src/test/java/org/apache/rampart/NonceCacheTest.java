package org.apache.rampart;

import junit.framework.TestCase;

/**
 * Created by IntelliJ IDEA.
 * User: aj
 * Date: Apr 30, 2010
 * Time: 4:15:20 PM
 * To change this template use File | Settings | File Templates.
 */
public class NonceCacheTest extends TestCase {

    public NonceCacheTest(String name) {
        super(name);
    }

    public void testAddToCache() throws Exception {

        UniqueMessageAttributeCache cache = new NonceCache();

        cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        cache.addToCache("j8EqKYJ/CxOdfN8CySMm0g==", "apache");
        cache.addToCache("j8EqKYJ/CxOhfN8CySMm0g==", "apache");
    }

    public void testValueExistsInCache() throws Exception{

        UniqueMessageAttributeCache cache = new NonceCache();

        cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        cache.addToCache("j8EqKYJ/CxOdfN8CySMm0g==", "apache");
        cache.addToCache("j8EqKYJ/CxOhfN8CySMm0g==", "apache");

        boolean returnValue1 = cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        assertTrue("nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must exists in the cache", returnValue1);

        boolean returnValue2 = cache.valueExistsInCache("p8EqKYJ/CxOZfN8CySMm0g==", "apache");
        assertFalse("nonce - p8EqKYJ/CxOZfN8CySMm0g== and apache should not be in the cache", returnValue2);
    }

    public void testValueExpiration() throws Exception{

        UniqueMessageAttributeCache cache = new NonceCache();

        cache.addToCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        cache.addToCache("j8EqKYJ/CxOdfN8CySMm0p==", "apache");
        cache.addToCache("q8EqKYJ/CxOhfN8CySMm0g==", "apache");

        cache.setMaximumLifeTimeOfAnAttribute(1);

        boolean returnValue1 = cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        assertTrue("nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must exists in the cache", returnValue1);

        Thread.sleep(2 * 1000);

        returnValue1 = cache.valueExistsInCache("j8EqKYJ/CxOZfN8CySMm0g==", "apache");
        assertFalse("nonce - j8EqKYJ/CxOZfN8CySMm0g== and apache must not exists in the cache", returnValue1);

    }
}
