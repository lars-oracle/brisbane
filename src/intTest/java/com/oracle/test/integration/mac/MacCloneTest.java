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

package com.oracle.test.integration.mac;

import java.util.Arrays;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

/**
 * Test Mac cloneable interface.
 */
public class MacCloneTest {

    private static final byte[] TEST_KEY = new byte[] {
            (byte)0x01, (byte)0x02, (byte)0x03, (byte)0x04, (byte)0x05, (byte)0x06, (byte)0x07, (byte)0x08,
            (byte)0x09, (byte)0x0A, (byte)0x0B, (byte)0x0C, (byte)0x0D, (byte)0x0E, (byte)0x0F, (byte)0x10
    };
    private static final byte[] ALT_TEST_KEY = new byte[] {
            (byte)0x10, (byte)0x0F, (byte)0x0E, (byte)0x0D, (byte)0x0C, (byte)0x0B, (byte)0x0A, (byte)0x09,
            (byte)0x08, (byte)0x07, (byte)0x06, (byte)0x05, (byte)0x04, (byte)0x03, (byte)0x02, (byte)0x01
    };
    private static final byte[] TEST_DATA = "hello world".getBytes();
    private static final byte[] ALT_TEST_DATA = "world hello".getBytes();

    private Mac mac;
    private SecretKey secretKey;
    private SecretKey altSecretKey;

    @Before
    public void setUp() throws Exception {
        // Use HmacSHA256 as a representative implementation, using the provider under test
        mac = ProviderUtil.getMac("HmacSHA256");
        secretKey = new SecretKeySpec(TEST_KEY, "HmacSHA256");
        altSecretKey = new SecretKeySpec(ALT_TEST_KEY, "HmacSHA256");

        mac.init(secretKey);
    }

    @Test
    public void cloneBeforeInit() throws Exception {
        // Obtain a fresh Mac instance but do NOT call init yet
        Mac uninitialized = ProviderUtil.getMac("HmacSHA256");

        Mac clone = (Mac) uninitialized.clone();

        // Both original and clone should behave like a fresh instance once init is called
        uninitialized.init(secretKey);
        clone.init(secretKey);

        uninitialized.update(TEST_DATA);
        clone.update(TEST_DATA);

        byte[] mac1 = uninitialized.doFinal();
        byte[] mac2 = clone.doFinal();

        Assert.assertArrayEquals("Cloning before init should yield equivalent state once initialized", mac1, mac2);
    }

    @Test
    public void cloneNoUpdate() throws Exception {
        Mac clone = (Mac) mac.clone();

        // Both original and clone without input should yield the same MAC for empty input
        byte[] mac1 = mac.doFinal();
        mac.reset();
        byte[] mac2 = clone.doFinal();

        Assert.assertArrayEquals("Original and clone MACs of empty input should match", mac1, mac2);

        mac.reset();
        clone.reset();
        // MACs after reset should again match for empty input
        Assert.assertArrayEquals(mac.doFinal(), clone.doFinal());
        byte[] rmac1 = mac.doFinal();
        byte[] rmac2 = clone.doFinal();
        Assert.assertArrayEquals(rmac1, rmac2);
    }

    @Test
    public void cloneAfterUpdate() throws Exception {
        mac.update(TEST_DATA, 0, TEST_DATA.length);
        Mac clone = (Mac) mac.clone();

        // Original and clone: same input processed, should match
        byte[] macOriginal = mac.doFinal();
        // Re-initialize original for next operation
        mac.init(secretKey);
        byte[] macClone = clone.doFinal();

        Assert.assertArrayEquals("MACs produced by original and clone after same updates should match", macOriginal, macClone);

        // Show independence: update clone with different data and check original stays unaffected
        clone.init(secretKey);
        clone.update(ALT_TEST_DATA, 0, ALT_TEST_DATA.length);
        byte[] macCloneAlt = clone.doFinal();
        mac.init(secretKey);
        mac.update(TEST_DATA, 0, TEST_DATA.length);
        byte[] macOriginalAgain = mac.doFinal();

        Assert.assertFalse("Changing update state in clone should not affect original", Arrays.equals(macOriginalAgain, macCloneAlt));
        Assert.assertArrayEquals("Original MAC with original data is unchanged", macOriginal, macOriginalAgain);
    }

    @Test
    public void cloneAndUpdateKey() throws Exception {
        mac.update(TEST_DATA, 0, TEST_DATA.length);
        Mac clone = (Mac) mac.clone();

        // Original and clone: same input processed, should match
        byte[] macOriginal = mac.doFinal();
        // Re-initialize original with alternative secret key
        mac.init(altSecretKey);
        byte[] macClone = clone.doFinal();

        Assert.assertArrayEquals("MACs produced by original and clone after same updates should match", macOriginal, macClone);

        // Re-initialize clone with alternative secret key and update with alternative data
        clone.init(altSecretKey);
        clone.update(ALT_TEST_DATA, 0, ALT_TEST_DATA.length);
        byte[] macCloneAlt = clone.doFinal();
        // mac already has the alternate secret key set above, but update with alternative data
        mac.update(ALT_TEST_DATA, 0, ALT_TEST_DATA.length);
        byte[] macOriginalAlt = mac.doFinal();

        Assert.assertArrayEquals("Original and Clone with alternative data and alternative secret key after cloning should match", macCloneAlt, macOriginalAlt);
    }

    @Test
    public void cloneAfterFinal() throws Exception {
        mac.update(TEST_DATA, 0, TEST_DATA.length);

        Mac cloneBeforeFinal = (Mac) mac.clone();

        byte[] originalMac = mac.doFinal();

        Mac cloneAfterFinal = (Mac) mac.clone();

        // If we clone the Mac before calling final() on the original, then call update() on the clone,
        // the clone must produce different output than the original. The clone has been updated with
        // different input (TEST_DATA added twice), so its final MAC should not match the original.
        cloneBeforeFinal.update(TEST_DATA, 0, TEST_DATA.length);
        byte[] cloneBeforeFinalMac = cloneBeforeFinal.doFinal();
        Assert.assertFalse("update on cloneBeforeFinal should differ from original mac output",
                Arrays.equals(originalMac, cloneBeforeFinalMac));

        // If we clone the Mac after calling final() on the original, then call update() on the clone,
        // the clone should produce the same output as the original (assuming both are updated with the
        // same TEST_DATA). A post-final clone inherits the original's state, including the pending
        // re-initialization, so the next update starts from a fresh MAC state and yields the same result.
        cloneAfterFinal.update(TEST_DATA, 0, TEST_DATA.length);
        byte[] cloneAfterFinalMac = cloneAfterFinal.doFinal();
        Assert.assertArrayEquals("update on cloneAfterFinal should match original mac output for same input",
                originalMac, cloneAfterFinalMac);
    }

}
