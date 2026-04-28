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

package com.oracle.test.integration.symciph;

import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.symMatcher;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;

/**
 * Test class for testing that doFinal methods reset the Cipher object to the state it was in when previously
 * initialized via a call to init.
 * <p>
 * Jipher does NOT support Cipher auto reset on doFinal for:
 *  - encryption for ALL modes other than ECB & CBC (which are supported due to legacy use that relies on the documented behavior)
 *  - decryption for CTR & GCM (OpenSSL fails to reset counter for CTR and explicitly denies reuse of a previously used IV for GCM)
 */
@RunWith(Parameterized.class)
public abstract class SymCipherAutoResetTest {

    SymCipherTestVector tv;
    int blockSize;
    byte[] otherCipherText;

    public SymCipherAutoResetTest(String transform) throws Exception {
        Assume.assumeTrue(EnvUtil.getPolicy() == EnvUtil.FipsPolicy.NONE || !transform.contains("DESede"));

        this.tv = TestData.getFirst(SymCipherTestVector.class, symMatcher().alg(transform).dataMin(16));

        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        blockSize = c.getBlockSize();
        this.otherCipherText = c.doFinal(new byte[blockSize]);
    }

    String getAlgorithm() {
        return this.tv.getAlg().split("/")[0];
    }

    String getMode() {
        return this.tv.getAlg().split("/")[1];
    }

    AlgorithmParameterSpec getInitSpec() {
        if (tv.getCiphParams() != null) {
            return new IvParameterSpec(tv.getCiphParams().getIv());
        } else {
            return null;
        }
    }

    Cipher getInitCipher(int opMode) throws Exception {
        Cipher cipher = ProviderUtil.getCipher(tv.getAlg());
        cipher.init(opMode, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, getAlgorithm()), getInitSpec());

        return cipher;
    }

    abstract boolean isAutoResetAllowedAfterData(int opMode);
    abstract boolean isAutoResetAllowedAfterZeroData(int opMode);

    public static class NoPadTest extends SymCipherAutoResetTest {

        @Parameterized.Parameters(name = "{0} ({index})")
        public static Collection<String> cases() throws Exception {
            return Arrays.asList(
                    "AES/CBC/NoPadding",
                    "AES/CFB/NoPadding",
                    "AES/CTR/NoPadding",
                    "AES/ECB/NoPadding",
                    "AES/OFB/NoPadding",
                    "DESede/ECB/NoPadding",
                    "DESede/CBC/NoPadding"
            );
        }

        public NoPadTest(String alg) throws Exception {
            super(alg);
        }

        @Override
        boolean isAutoResetAllowedAfterData(int opMode) {
            switch (getMode().toUpperCase()) {
                case "CTR":
                    return false;
                case "ECB":
                case "CBC":
                    return true;
                case "CFB":
                case "OFB":
                    return (opMode == Cipher.DECRYPT_MODE);
                default:
                    fail("Test does not support mode: " + getMode());
            }
            return false;
        }

        @Override
        boolean isAutoResetAllowedAfterZeroData(int opMode) {
            switch (getMode().toUpperCase()) {
                case "CBC":
                case "CFB":
                case "CTR":
                case "ECB":
                case "OFB":
                    return true;
                default:
                    fail("Test does not support mode: " + getMode());
            }
            return false;
        }

        @Test
        public void decryptReuseWithoutInitAfterDoFinalEmptyArray() throws Exception {
            reuseWithoutInitAfterDoFinalEmptyArray(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
        }

        @Test
        public void decryptReuseWithoutInitAfterDoFinalZeroIn() throws Exception {
            reuseWithoutInitAfterDoFinalZeroIn(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
        }

        @Test
        public void decryptReuseWithoutInitAfterDoFinal() throws Exception {
            reuseWithoutInitAfterDoFinal(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
        }
    }

    public static class PadTest extends SymCipherAutoResetTest {

        @Parameterized.Parameters(name = "{0} ({index})")
        public static Collection<String> cases() throws Exception {
            return Arrays.asList(
                    "AES/CBC/PKCS5Padding",
                    "AES/ECB/PKCS5Padding",
                    "DESede/ECB/PKCS5Padding",
                    "DESede/CBC/PKCS5Padding"
            );
        }

        public PadTest(String alg) throws Exception {
            super(alg);
        }

        @Override
        boolean isAutoResetAllowedAfterData(int opMode) {
            switch (getMode().toUpperCase()) {
                case "ECB":
                case "CBC":
                    return true;
                default:
                    fail("Test does not support mode: " + getMode());
            }
            return false;
        }

        @Override
        boolean isAutoResetAllowedAfterZeroData(int opMode) {
            switch (getMode().toUpperCase()) {
                case "ECB":
                case "CBC":
                    return true;
                default:
                    fail("Test does not support mode: " + getMode());
            }
            return false;
        }
    }

    public static class AeadTest extends SymCipherAutoResetTest {

        @Parameterized.Parameters(name="{0} ({index})")
        public static Collection<String> cases() throws Exception {
            return Arrays.asList(
                    "AES/GCM/NoPadding"
            );
        }

        public AeadTest(String alg) throws Exception {
            super(alg);
        }

        @Override
        AlgorithmParameterSpec getInitSpec() {
            return new GCMParameterSpec(tv.getCiphParams().getTagLen(), tv.getCiphParams().getIv());
        }

        @Override
        Cipher getInitCipher(int opMode) throws Exception {
            Cipher cipher = super.getInitCipher(opMode);
            if (tv.getAad() != null) {
                cipher.updateAAD(tv.getAad());
            }
            return cipher;
        }

        @Override
        boolean isAutoResetAllowedAfterData(int opMode) {
            return false;
        }

        @Override
        boolean isAutoResetAllowedAfterZeroData(int opMode) {
            return false;
        }
    }

    public void reuseWithoutInitAfterDoFinalEmptyArray(int opMode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher c = getInitCipher(opMode);
        boolean allowed = isAutoResetAllowedAfterZeroData(opMode);
        byte[] output = new byte[c.getOutputSize(input.length)];
        c.doFinal(new byte[0], 0, 0, output, 0);

        try {
            int outputOffset = c.update(input, 0, input.length, output, 0);
            assertTrue(allowed);
            int outputLen = outputOffset + c.doFinal(output, outputOffset);
            assertTrue(allowed);
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(output, 0, outputLen));
        } catch (IllegalStateException e) {
            assertFalse(allowed);
        }
    }

    public void reuseWithoutInitAfterDoFinalZeroIn(int opMode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher c = getInitCipher(opMode);
        boolean allowed = isAutoResetAllowedAfterZeroData(opMode);
        byte[] output = new byte[c.getOutputSize(input.length)];
        c.doFinal(input, 0, 0, output, 0);
        try {
            int outputLen = c.doFinal(input, 0, input.length, output, 0);
            assertTrue(allowed);
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(output, 0, outputLen));
        } catch (IllegalStateException e) {
            assertFalse(allowed);
        }
    }

    public void reuseWithoutInitAfterDoFinal(int opMode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher c = getInitCipher(opMode);
        boolean allowed = isAutoResetAllowedAfterZeroData(opMode);
        c.doFinal();
        try {
            byte[] output = new byte[c.getOutputSize(input.length)];
            int outputOffset = c.update(input, 0, input.length, output, 0);
            assertTrue(allowed);
            int outputLen = outputOffset + c.doFinal(output, outputOffset);
            assertTrue(allowed);
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(output, 0, outputLen));
        } catch (IllegalStateException e) {
            assertFalse(allowed);
        }
    }

    public void reuseAfterInitDoFinalWithData(int opMode, byte[] input, byte[] expectedOutput, byte[] otherInput) throws Exception {
        Cipher c = getInitCipher(opMode);
        boolean allowed = isAutoResetAllowedAfterData(opMode);
        byte[] output = new byte[c.getOutputSize(input.length)];
        c.doFinal(otherInput, 0, otherInput.length, output, 0);

        try {
            int outputOffset = c.update(input, 0, input.length, output, 0);
            assertTrue(allowed);
            int outputLen = outputOffset + c.doFinal(output, outputOffset);
            assertTrue(allowed);
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(output, 0, outputLen));
        } catch (IllegalStateException e) {
            assertFalse(allowed);
        }
    }

    @Test
    public void encryptReuseWithoutInitAfterDoFinalEmptyArray() throws Exception {
        reuseWithoutInitAfterDoFinalEmptyArray(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptReuseWithoutInitAfterDoFinalZeroIn() throws Exception {
        reuseWithoutInitAfterDoFinalZeroIn(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptReuseWithoutInitAfterDoFinal() throws Exception {
        reuseWithoutInitAfterDoFinal(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptReuseAfterInitDoFinalWithData() throws Exception {
        reuseAfterInitDoFinalWithData(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext(), new byte[blockSize]);
    }

    @Test
    public void decryptReuseAfterInitDoFinalWithData() throws Exception {
        reuseAfterInitDoFinalWithData(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData(), this.otherCipherText);
    }
}
