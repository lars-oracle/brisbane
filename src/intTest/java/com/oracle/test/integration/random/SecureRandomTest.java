/*
 * Copyright (c) 2026 Oracle and/or its affiliates.
 *
 * The Universal Permissive License (UPL), Version 1.0
 *
 * Subject to the condition set forth below, permission is hereby granted to any
 * person obtaining a copy of this software, associated documentation and/or data
 * (collectively the "Software"), free of charge and under any and all copyright
 * rights in the Software, and any and all patent rights owned or freely
 * licensable by each licensor hereunder covering either (i) the unmodified
 * Software as contributed to or provided by such licensor, or (ii) the Larger
 * Works (as defined below), to deal in both
 *
 * (a) the Software, and
 *
 * (b) any piece of software and/or hardware listed in the lrgrwrks.txt file if
 * one is included with the Software (each a "Larger Work" to which the Software
 * is contributed by such licensors),
 *
 * without restriction, including without limitation the rights to copy, create
 * derivative works of, display, perform, and distribute the Software and make,
 * use, sell, offer for sale, import, export, have made, and have sold the
 * Software and the Larger Work(s), and to sublicense the foregoing rights on
 * either these or other terms.
 *
 * This license is subject to the following condition:
 *
 * The above copyright notice and either this complete permission notice or at
 * a minimum a reference to the UPL must be included in all copies or
 * substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 * SOFTWARE.
 */

package com.oracle.test.integration.random;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.Provider;
import java.security.SecureRandom;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertEquals;

/**
 * Test the SecureRandom APIs.
 */
public class SecureRandomTest {

    SecureRandom secureRandom;

    @Before
    public void setUp() throws Exception {
        secureRandom = ProviderUtil.getSecureRandom("DRBG");
    }

    @Test
    public void newInstance() throws Exception {
        ProviderUtil.getSecureRandom("DRBG");
        ProviderUtil.getSecureRandom("DRBG");
        ProviderUtil.getSecureRandom("DRBG");
        ProviderUtil.getSecureRandom("DRBG");
        ProviderUtil.getSecureRandom("DRBG");
    }

    @Test
    public void reviveInstance() throws Exception {
        ByteArrayOutputStream out = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(out);
        objOut.writeObject(secureRandom);
        ByteArrayInputStream bIn = new ByteArrayInputStream(out.toByteArray());
        ObjectInputStream in = new ObjectInputStream(bIn);
        SecureRandom deserializedSecureRandom = (SecureRandom) in.readObject();

        // Confirm that deserialized SecureRandom does not throw when employed.
        byte[] deserializedSecureRandomBytes = new byte[100];
        deserializedSecureRandom.nextBytes(deserializedSecureRandomBytes);

        // Confirm that serializing the secure random does not serialize the state.
        byte[] secureRandomBytes = new byte[100];
        secureRandom.nextBytes(secureRandomBytes);

        Assert.assertFalse(Arrays.equals(secureRandomBytes, deserializedSecureRandomBytes));
    }

    @Test
    public void setSeed() {
        secureRandom.setSeed(23L);
        secureRandom.setSeed("blahblahblah".getBytes());
    }

    @Test
    public void generateSeed() throws Exception {
        byte[] ret = secureRandom.generateSeed(14);
        assertEquals(14, ret.length);
    }

    @Test(expected=RuntimeException.class)
    public void generateSeedNegative() throws Exception {
        secureRandom.generateSeed(-14);
    }

    @Test
    public void nextBytes() throws Exception {
        byte[] out = new byte[45];
        secureRandom.nextBytes(out);
        assertEquals(45, out.length);
    }

    @Test(expected= NullPointerException.class)
    public void nextBytesNull() throws Exception {
        secureRandom.nextBytes(null);
    }

    /**
     * Test that DRBG instance can be used on multiple threads.
     */
    @Test
    public void multithreads() throws Exception {
        Thread[] ts = new Thread[20];
        final byte[] out = new byte[34];
        for (int i = 0; i < ts.length; i++) {
            ts[i] = new Thread(() -> {
                for (int j = 0; j < 10; j++) {
                    secureRandom.nextBytes(out);
                    secureRandom.generateSeed(24);
                    try {
                        Thread.sleep(1);
                    } catch (InterruptedException e) {
                        // ignore
                    }
                }
            });
            ts[i].start();
        }
        for (Thread t : ts) {
            t.join();
        }
    }

    /**
     * Test that the expected aliases are registered for DRBG impl.
     */
    @Test
    public void aliases() {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("SecureRandom", "DRBG");

        String[] aliases = new String[]{
                "Default", "DefaultRandom", "SHA1PRNG", "CTRDRBG", "CTRDRBG128",
                "NativePRNG", "NativePRNGNonBlocking"};
        for (String a : aliases) {
            Provider.Service s = provider.getService("SecureRandom", a);
            Assert.assertNotNull("Provider does not contain SecureRandom." + a, s);
            assertEquals("Provider returns incorrect impl for SecureRandom." + a, service.getClassName(), s.getClassName());
        }
    }

    /**
     * Test that the attribute ThreadSafe=true exists for DRBG.
     */
    @Test
    public void drbgThreadSafeAttribute() {
        Provider provider = ProviderUtil.get();
        assertEquals("true", provider.get("SecureRandom.DRBG ThreadSafe"));
    }
}
