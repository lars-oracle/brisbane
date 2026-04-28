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

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.DataSize;
import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class SymCipherAlgVariantVectorTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return Arrays.asList(
                new Object[]{
                        "AES_128/ECB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                            DataMatchers.symMatcher().alg("AES/ECB/NoPadding").keySize(16)),
                },
                new Object[]{
                        "AES_192/ECB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/ECB/NoPadding").keySize(24)),
                },
                new Object[]{
                        "AES_256/ECB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/ECB/NoPadding").keySize(32)),
                },
                new Object[]{
                        "AES",
                        TestData.getFirst(SymCipherTestVector.class,
                            DataMatchers.symMatcher().alg("AES/ECB/PKCS5Padding").keySize(16)),
                },
                new Object[]{
                        "AES",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/ECB/PKCS5Padding").keySize(24)),
                },
                new Object[]{
                        "AES",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/ECB/PKCS5Padding").keySize(32)),
                },
                new Object[]{
                        "AES/CTR/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CTR/NoPadding").keySize(16)),
                },
                new Object[]{
                        "AES/CTR/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CTR/NoPadding").keySize(24)),
                },
                new Object[]{
                        "AES/CTR/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CTR/NoPadding").keySize(32)),
                },
                new Object[]{
                        "AES_128/CBC/PKCS5Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(16)),
                },
                new Object[]{
                        "AES_192/CBC/PKCS5Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(24)),
                },
                new Object[]{
                        "AES_256/CBC/PKCS5Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(32)),
                },
                new Object[]{
                        "AES_128/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(16)),
                },
                new Object[]{
                        "AES_192/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(24)),
                },
                new Object[]{
                        "AES_256/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(32)),
                },
                new Object[]{
                        "AES/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(16)),
                },
                new Object[]{
                        "AES/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(24)),
                },
                new Object[]{
                        "AES/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CBC/PKCS5Padding").keySize(32)),
                },
                new Object[]{
                        "AES_128/CFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CFB/NoPadding").keySize(16)),
                },
                new Object[]{
                        "AES_192/CFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CFB/NoPadding").keySize(24)),
                },
                new Object[]{
                        "AES_256/CFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/CFB/NoPadding").keySize(32)),
                },
                new Object[]{
                        "AES_128/OFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/OFB/NoPadding").keySize(16)),
                },
                new Object[]{
                        "AES_192/OFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/OFB/NoPadding").keySize(24)),
                },
                new Object[]{
                        "AES_256/OFB/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/OFB/NoPadding").keySize(32)),
                },
                new Object[]{
                        "AES_128/GCM/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/GCM/NoPadding").keySize(16).aad(DataSize.EMPTY)),
                },
                new Object[]{
                        "AES_192/GCM/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/GCM/NoPadding").keySize(24).aad(DataSize.EMPTY)),
                },
                new Object[]{
                        "AES_256/GCM/NoPadding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("AES/GCM/NoPadding").keySize(32).aad(DataSize.EMPTY)),
                },
                new Object[]{
                        "DESede",
                        TestData.getFirst(SymCipherTestVector.class,
                            DataMatchers.symMatcher().alg("DESede/ECB/PKCS5Padding").keySize(24)),
                },
                new Object[]{
                        "DESede/CBC/PKCS7Padding",
                        TestData.getFirst(SymCipherTestVector.class,
                                DataMatchers.symMatcher().alg("DESede/CBC/PKCS5Padding").keySize(24)),
                }
        );
    }

    private final String alg;
    private final SymCipherTestVector tv;

    public SymCipherAlgVariantVectorTest(String alg, SymCipherTestVector tv) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().startsWith("DESEDE"));
        this.alg = alg;
        this.tv = tv;
    }

    @Test
    public void test() throws Exception {
        Cipher c = ProviderUtil.getCipher(this.alg);
        c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(this.tv.getKey(), "AES"), getParamSpec());
        byte[] decrypted = c.doFinal(this.tv.getCiphertext());
        assertArrayEquals(tv.getData(), decrypted);
    }

    AlgorithmParameterSpec getParamSpec() {
        SymCipherTestVector.CipherParams params = tv.getCiphParams();
        if (params != null) {
            if (alg.endsWith("GCM/NoPadding")) {
               return new GCMParameterSpec(params.getTagLen(), params.getIv());
            } else {
                return new IvParameterSpec(tv.getCiphParams().getIv());
            }
        }
        return null;
    }

}
