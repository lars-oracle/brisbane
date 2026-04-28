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

import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

/**
 * Test class for methods on Cipher other than init, update, final, wrap, unwrap.
 */
@RunWith(Parameterized.class)
public class SymCipherMethodTest {

    private static final byte[] SAMPLE_IV = TestUtil.hexStringToByteArray("00112233445566778899aabbccddeeff");

    private static byte[] ivBytes(int len) {
        return Arrays.copyOf(SAMPLE_IV, len);
    }

    @Parameterized.Parameters(name="{0} ({index})")
    public static Collection<Object[]> cases() {
        Collection<Object[]> testCases = Arrays.asList(
            new Object[]{
                "AES/CBC/PKCS5Padding", 16, 16, ivBytes(16), new IvParameterSpec(ivBytes(16)), "AES"
            },
            new Object[]{
                "AES/ECB/PKCS5Padding", 24, 16, null, null, "AES"
            },
            new Object[]{
                "AES/GCM/NoPadding", 16, 16, ivBytes(12), new GCMParameterSpec(128, ivBytes(12)), "GCM"
            },
            new Object[]{
                "AES/GCM/NoPadding", 32, 16, ivBytes(12), new GCMParameterSpec(96, ivBytes(12)), "GCM"
            },
            new Object[]{
                "PBEWithHmacSHA256AndAES_128", 20, 16, ivBytes(16), new PBEParameterSpec(ivBytes(20), 1000, new IvParameterSpec(ivBytes(16))), "PBEWithHmacSHA256AndAES_128"
            }
        );

        if (EnvUtil.getPolicy() == EnvUtil.FipsPolicy.NONE) {
            testCases.add(
                    new Object[]{
                            "DESede/CBC/PKCS5Padding", 24, 8, ivBytes(8), new IvParameterSpec(ivBytes(8)), "DESede"
                    }
            );
        }

        return testCases;
    }

    private final String alg;
    private final int keySize;
    private final int blocksize;

    private final String paramsAlg;
    private final AlgorithmParameterSpec spec;
    private final byte[] iv;

    public SymCipherMethodTest(String alg, int keySize, int blocksize, byte[] iv, AlgorithmParameterSpec spec, String paramsAlg) {
        this.alg = alg;
        this.keySize = keySize;
        this.blocksize = blocksize;
        this.iv = iv;
        this.paramsAlg = paramsAlg;
        this.spec = spec;
    }

    @Test
    public void getBlockSize() throws Exception {
        Cipher c = ProviderUtil.getCipher(this.alg);
        assertEquals(this.blocksize, c.getBlockSize());
    }

    @Test
    public void getIv() throws Exception {
        Cipher c = ProviderUtil.getCipher(this.alg);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[this.keySize], paramsAlg), spec);
        Assert.assertArrayEquals(iv, c.getIV());
    }

    @Test
    public void initAlgorithmParameters() throws Exception {
        if (this.spec == null) {
            return;
        }
        Cipher c = ProviderUtil.getCipher(this.alg);
        AlgorithmParameters algParams = ProviderUtil.getAlgorithmParameters(paramsAlg);
        algParams.init(spec);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[this.keySize], paramsAlg), algParams);
        AlgorithmParameters params = c.getParameters();
        checkParams(params);
    }

    @Test
    public void getParameters() throws Exception {
        Cipher c = ProviderUtil.getCipher(this.alg);
        c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(new byte[this.keySize], paramsAlg), spec);
        AlgorithmParameters params = c.getParameters();
        if (this.spec == null) {
            assertNull(params);
            return;
        }
        checkParams(params);
    }

    void checkParams(AlgorithmParameters params) throws Exception {
        AlgorithmParameterSpec paramSpec = params.getParameterSpec(this.spec.getClass());
        assertEquals(paramsAlg, params.getAlgorithm());
        if (this.spec instanceof IvParameterSpec) {
            IvParameterSpec ivSpec = (IvParameterSpec) paramSpec;
            assertArrayEquals(iv, ivSpec.getIV());
        } else if (this.spec instanceof GCMParameterSpec) {
            GCMParameterSpec gcmSpec = (GCMParameterSpec) paramSpec;
            assertEquals(((GCMParameterSpec) this.spec).getTLen(), gcmSpec.getTLen());
            assertArrayEquals(((GCMParameterSpec) this.spec).getIV(), gcmSpec.getIV());
        } else if (this.spec instanceof PBEParameterSpec) {
            PBEParameterSpec pbeSpec = (PBEParameterSpec) paramSpec;
            IvParameterSpec ivSpec = (IvParameterSpec) pbeSpec.getParameterSpec();
            assertArrayEquals(((PBEParameterSpec) this.spec).getSalt(), pbeSpec.getSalt());
            assertEquals(((PBEParameterSpec) this.spec).getIterationCount(), pbeSpec.getIterationCount());
            assertArrayEquals(((IvParameterSpec)((PBEParameterSpec) this.spec).getParameterSpec()).getIV(), ivSpec.getIV());
        } else {
            throw new Error("Incomplete testing of parameter specs.");
        }
    }
}
