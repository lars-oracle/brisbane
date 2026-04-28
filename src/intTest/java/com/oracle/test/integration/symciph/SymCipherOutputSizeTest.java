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
import java.util.ArrayList;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.model.AuthenticatedStreamCipherModel;
import com.oracle.jiphertest.model.BlockCipherModel;
import com.oracle.jiphertest.model.CipherModel;
import com.oracle.jiphertest.model.StreamCipherModel;
import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.symMatcher;
import static org.junit.Assert.assertEquals;

/**
 * Test output sizes from methods getOutputSize(), update() and doFinal() on Cipher.
 */
@RunWith(Parameterized.class)
public abstract class SymCipherOutputSizeTest {

    static int getBlockSize(String algorithm) {
        return switch (algorithm.toUpperCase()) {
            case "AES" -> 16;
            case "DESEDE" -> 8;
            default -> throw new RuntimeException("Unsupported algorithm");
        };
    }

    final SymCipherTestVector tv;
    AlgorithmParameterSpec initSpec;

    public SymCipherOutputSizeTest(String name, SymCipherTestVector tv) throws Exception {
        this.tv = tv;
        this.initSpec = createSpec(tv);
    }

    AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
        if (tv.getCiphParams() != null) {
            return new IvParameterSpec(tv.getCiphParams().getIv());
        } else {
            return null;
        }
    }

    Cipher getInitCipher(int opMode) throws Exception {
        Assume.assumeTrue(EnvUtil.getPolicy() == EnvUtil.FipsPolicy.NONE || !tv.getAlg().contains("DESede"));

        Cipher cipher = ProviderUtil.getCipher(tv.getAlg());
        cipher.init(opMode, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, getAlgorithm()), initSpec);
        return cipher;
    }

    abstract CipherModel getCipherModel();

    public static class BlockModeTest extends SymCipherOutputSizeTest {

        static final String[] ALGORITHMS = new String[]{"AES", "DESede"};
        static final String[] BLOCK_MODES = new String[]{"ECB", "CBC"};
        static final String[] PADDING_MODES = new String[]{"NoPadding", "PKCS5Padding"};

        static boolean isPaddingEnabled(String paddingMode) {
            return !paddingMode.equalsIgnoreCase("NoPadding");
        }

        @Parameterized.Parameters(name = "{0})")
        public static Collection<Object[]> cases() throws Exception {
            ArrayList<Object[]> list = new ArrayList<>();

            for (String algorithm : ALGORITHMS) {
                int blockSize = getBlockSize(algorithm);
                for (String blockMode : BLOCK_MODES) {
                    for (String paddingMode: PADDING_MODES) {
                        String transformation = algorithm + "/" + blockMode + "/" + paddingMode;
                        SymCipherTestVector tv = TestData.getFirst(SymCipherTestVector.class, symMatcher().alg(transformation).dataMin(blockSize * 2).blockAligned(blockSize));
                        list.add(new Object[]{transformation + " - Aligned", tv});

                        if (isPaddingEnabled(paddingMode)) {
                            tv = TestData.getFirst(SymCipherTestVector.class, symMatcher().alg(transformation).dataMin(blockSize * 2).blockUnaligned(blockSize));
                            list.add(new Object[]{transformation + " - Unaligned", tv});
                        }
                    }
                }
            }
            return list;
        }

        public BlockModeTest(String name, SymCipherTestVector tv) throws Exception {
            super(name, tv);
        }

        @Override
        protected CipherModel getCipherModel() {
            return new BlockCipherModel(getBlockSize(getAlgorithm()), isPaddingEnabled(getPadding()));
        }
    }

    public static class StreamModeTest extends SymCipherOutputSizeTest {

        static final String[] ALGORITHMS = new String[]{"AES"};
        static final String[] BLOCK_MODES = new String[]{"CFB", "OFB"};

        @Parameterized.Parameters(name = "{0})")
        public static Collection<Object[]> cases() throws Exception {
            ArrayList<Object[]> list = new ArrayList<>();

            for (String algorithm : ALGORITHMS) {
                int blockSize = getBlockSize(algorithm);
                for (String blockMode : BLOCK_MODES) {
                    String transformation = algorithm + "/" + blockMode + "/NoPadding";
                    SymCipherTestVector tv = TestData.getFirst(SymCipherTestVector.class, symMatcher().alg(transformation).dataMin(blockSize * 2).blockUnaligned(blockSize));
                    list.add(new Object[]{transformation, tv});
                }
            }
            return list;
        }

        public StreamModeTest(String name, SymCipherTestVector tv) throws Exception {
            super(name, tv);
        }

        @Override
        protected CipherModel getCipherModel() {
            return new StreamCipherModel();
        }
    }

    public static class AeadModeTest extends SymCipherOutputSizeTest {

        @Parameterized.Parameters(name = "{0})")
        public static Collection<Object[]> cases() throws Exception {
            ArrayList<Object[]> list = new ArrayList<>();

            int blockSize = getBlockSize("AES");
            String transformation = "AES/GCM/NoPadding";
            SymCipherTestVector tv = TestData.getFirst(SymCipherTestVector.class, symMatcher().alg(transformation).dataMin(blockSize * 2).blockUnaligned(blockSize));

            list.add(new Object[]{transformation, tv});

            return list;
        }

        public AeadModeTest(String name, SymCipherTestVector tv) throws Exception {
            super(name, tv);
        }

        @Override
        AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
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
        protected CipherModel getCipherModel() {
            return new AuthenticatedStreamCipherModel(tv.getCiphParams().getTagLen() >> 3);
        }
    }

    String getAlgorithm() {
        return this.tv.getAlg().split("/")[0];
    }

    String getPadding() {
        return this.tv.getAlg().split("/")[2];
    }

    /*
     * Tests the output sizes from methods getOutputSize(), update() and doFinal() on Cipher
     * for the specified 'opMode' (encrypt/decrypt) at the specified 'inputOffset'.
     * If 'doFinalWithoutInput' is true it provides all the input before calling doFinal().
     *    update(0, inputOffset), update(inputOffset, remainingInputLen), doFinal()
     * otherwise it provides some of the input to doFina()
     *    update(0, inputOffset), doFinal(inputOffset, remainingInputLen)
     */
    public void outputSize(Cipher cipher, int opMode, byte[] input, byte[] output, int inputOffset, boolean doFinalWithoutInput)
            throws Exception {
        CipherModel cipherModel = getCipherModel();
        cipherModel.init(opMode == Cipher.DECRYPT_MODE);

        int expectedOutputLen = cipherModel.getOutputSize(inputOffset);
        int observedOutputLen = cipher.getOutputSize(inputOffset);

        assertEquals("1st:getOutputSize("+inputOffset+")", expectedOutputLen, observedOutputLen);

        expectedOutputLen = cipherModel.update(inputOffset);
        observedOutputLen = cipher.update(input, 0, inputOffset, new byte[expectedOutputLen], 0);

        assertEquals("update("+inputOffset+")", expectedOutputLen, observedOutputLen);

        int outputOffset = expectedOutputLen;
        int remainingInputLen = input.length - inputOffset;

        expectedOutputLen = cipherModel.getOutputSize(remainingInputLen);
        observedOutputLen = cipher.getOutputSize(remainingInputLen);

        assertEquals("2nd:getOutputSize("+remainingInputLen+")", expectedOutputLen, observedOutputLen);

        if (doFinalWithoutInput) {
            expectedOutputLen = cipherModel.update(remainingInputLen);
            observedOutputLen = cipher.update(input, inputOffset, remainingInputLen, new byte[expectedOutputLen], 0);

            assertEquals("update(" + remainingInputLen + ")", expectedOutputLen, observedOutputLen);

            outputOffset += expectedOutputLen;

            expectedOutputLen = cipherModel.getOutputSize(0);
            observedOutputLen = cipher.getOutputSize(0);

            assertEquals("getOutputSize(0)", expectedOutputLen, observedOutputLen);

            expectedOutputLen = output.length - outputOffset;
            observedOutputLen = cipher.doFinal(new byte[expectedOutputLen], 0);

            assertEquals("doFinal()", expectedOutputLen, observedOutputLen);
        } else {
            expectedOutputLen = output.length - outputOffset;
            observedOutputLen = cipher.doFinal(input, inputOffset, remainingInputLen, new byte[expectedOutputLen], 0);

            assertEquals("doFinal(" + remainingInputLen + ")", expectedOutputLen, observedOutputLen);
        }
    }

    public void runTests(int opMode, byte[] input, byte[] output) throws Exception
    {
        // Representative test cases happen within a byte of a block boundary.
        int blockSize = getBlockSize(getAlgorithm());
        for (int inputOffset : new int[]{blockSize - 1, blockSize, blockSize + 1}) {
            outputSize(getInitCipher(opMode), opMode, input, output, inputOffset, false);
            outputSize(getInitCipher(opMode), opMode, input, output, inputOffset, true);
        }
    }

    @Test
    public void encrypt() throws Exception
    {
        runTests(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decrypt() throws Exception
    {
        runTests(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }
}
