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

package com.oracle.test.integration.kdf;

import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.KDF;
import javax.crypto.SecretKey;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.HkdfTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Test HKDF implementations in the provider using test vectors.
 */
@RunWith(Parameterized.class)
public class KdfVectorTest {

    @Parameterized.Parameters(name="{0}:{index}")
    public static Collection<Object[]> data() throws Exception {
        Collection<Object[]> testVectors = new ArrayList<>();

        /*
         * RFC 5869: Appendix A. Test Vectors
         * https://www.rfc-editor.org/rfc/rfc5869.html#appendix-A
         */
        testVectors.add(
                new Object[] {
                        "RFC 5869: Test Case 1: Basic test case with SHA-256",
                        new HkdfTestVector(
                                "HKDF-SHA256",
                                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // input key material
                                "000102030405060708090a0b0c", // salt
                                "f0f1f2f3f4f5f6f7f8f9", // info
                                42, // output key material length
                                "077709362c2e32df0ddc3f0dc47bba6390b6c73bb50f9c3122ec844ad7c2b3e5", // pseudo random key
                                "3cb25f25faacd57a90434f64d0362f2a2d2d0a90cf1a5a4c5db02d56ecc4c5bf34007208d5b887185865") // output key material
                });
        testVectors.add(
                new Object[] {
                        "RFC 5869: Test Case 2: Test with SHA-256 and longer inputs/outputs",
                        new HkdfTestVector(
                                "HKDF-SHA256",
                                "000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f202122232425262728292a2b2c2d2e2f303132333435363738393a3b3c3d3e3f404142434445464748494a4b4c4d4e4f", // input key material
                                "606162636465666768696a6b6c6d6e6f707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f909192939495969798999a9b9c9d9e9fa0a1a2a3a4a5a6a7a8a9aaabacadaeaf", // salt
                                "b0b1b2b3b4b5b6b7b8b9babbbcbdbebfc0c1c2c3c4c5c6c7c8c9cacbcccdcecfd0d1d2d3d4d5d6d7d8d9dadbdcdddedfe0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfcfdfeff", // info
                                82, // output key material length
                                "06a6b88c5853361a06104c9ceb35b45cef760014904671014a193f40c15fc244", // pseudo random key
                                "b11e398dc80327a1c8e7f78c596a49344f012eda2d4efad8a050cc4c19afa97c59045a99cac7827271cb41c65e590e09da3275600c2f09b8367793a9aca3db71cc30c58179ec3e87c14c01d5c1f3434f1d87") // output key material
                });
        testVectors.add(
                new Object[] {
                        "RFC 5869: Test Case 3: Test with SHA-256 and zero-length salt/info",
                        new HkdfTestVector(
                                "HKDF-SHA256",
                                "0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b0b", // input key material
                                "", // salt
                                "", // info
                                42, // output key material length
                                "19ef24a32c717b167f33a91d6f648bdf96596776afdb6377ac434c1c293ccb04", // pseudo random key
                                "8da4e775a563c18f715f802a063c5a31b8a11f5c5ee1879ec3454e5f3c738d2d9d201395faa4b61a96c8") // output key material
                });
        // RFC 5869: Test Case 4 and later use SHA-1 which is not supported.

        // Add provider generated test vectors
        testVectors.addAll(TestData.forParameterized(HkdfTestVector.class));
        return testVectors;
    }

    private final HkdfTestVector tv;

    public KdfVectorTest(String description, HkdfTestVector tv) {
        this.tv = tv;
    }


    @Test
    public void extractDeriveData() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(tv.getAlg());
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract()
                .addIKM(tv.getIkm()).addSalt(tv.getSalt()).extractOnly();
        assertArrayEquals(tv.getPrk(), kdf.deriveData(derivationSpec));
    }

    @Test
    public void expandOnlyDeriveData() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        SecretKeySpec keySpec = new SecretKeySpec(tv.getPrk(), "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(keySpec, tv.getInfo(), tv.getOkmLen());
        assertArrayEquals(tv.getOkm(), kdf.deriveData(derivationSpec));
    }

    @Test
    public void extractThenExpandDeriveData() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract()
                .addIKM(tv.getIkm()).addSalt(tv.getSalt()).thenExpand(tv.getInfo(), tv.getOkmLen());
        assertArrayEquals(tv.getOkm(), kdf.deriveData(derivationSpec));
    }

    @Test
    public void extractDeriveKey() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract()
                .addIKM(tv.getIkm()).addSalt(tv.getSalt()).extractOnly();
        SecretKey key = kdf.deriveKey("generic", derivationSpec);
        assertEquals("generic", key.getAlgorithm());
        assertArrayEquals(tv.getPrk(), key.getEncoded());
    }

    @Test
    public void expandOnlyDeriveKey() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        SecretKeySpec keySpec = new SecretKeySpec(tv.getPrk(), "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(keySpec, tv.getInfo(), tv.getOkmLen());
        SecretKey key = kdf.deriveKey("generic", derivationSpec);
        assertEquals("generic", key.getAlgorithm());
        assertArrayEquals(tv.getOkm(), key.getEncoded());
    }

    @Test
    public void extractThenExpandDeriveKey() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract()
                .addIKM(tv.getIkm()).addSalt(tv.getSalt()).thenExpand(tv.getInfo(), tv.getOkmLen());
        SecretKey key = kdf.deriveKey("generic", derivationSpec);
        assertEquals("generic", key.getAlgorithm());
        assertArrayEquals(tv.getOkm(), key.getEncoded());
    }

    @Test
    public void multiInputExtract() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(tv.getAlg());
        HKDFParameterSpec.Builder builder = HKDFParameterSpec.ofExtract();

        int len = tv.getIkm().length;
        if (len < 1) {
            builder = builder.addIKM(tv.getIkm());
        } else {
            builder = builder
                    .addIKM(Arrays.copyOfRange(tv.getIkm(), 0, len / 2))
                    .addIKM(Arrays.copyOfRange(tv.getIkm(), len / 2, len));
        }
        len = tv.getSalt().length;
        if (len < 1) {
            builder = builder.addSalt(tv.getSalt());
        } else {
            builder = builder
                    .addSalt(Arrays.copyOfRange(tv.getSalt(), 0, len / 2))
                    .addSalt(Arrays.copyOfRange(tv.getSalt(), len / 2, len));
        }

        AlgorithmParameterSpec derivationSpec = builder.extractOnly();
        assertArrayEquals(tv.getPrk(), kdf.deriveData(derivationSpec));
    }

    @Test
    public void multiInputExtractThenExpand() throws Exception {
        KDF kdf = (KDF)  ProviderUtil.getKdf(tv.getAlg());
        HKDFParameterSpec.Builder builder = HKDFParameterSpec.ofExtract();

        int len = tv.getIkm().length;
        if (len < 1) {
            builder = builder.addIKM(tv.getIkm());
        } else {
            builder = builder
                    .addIKM(Arrays.copyOfRange(tv.getIkm(), 0, len / 2))
                    .addIKM(Arrays.copyOfRange(tv.getIkm(), len / 2, len));
        }
        len = tv.getSalt().length;
        if (len < 1) {
            builder = builder.addSalt(tv.getSalt());
        } else {
            builder = builder
                    .addSalt(Arrays.copyOfRange(tv.getSalt(), 0, len / 2))
                    .addSalt(Arrays.copyOfRange(tv.getSalt(), len / 2, len));
        }

        AlgorithmParameterSpec derivationSpec = builder.thenExpand(tv.getInfo(), tv.getOkmLen());
        assertArrayEquals(tv.getOkm(), kdf.deriveData(derivationSpec));
    }
}
