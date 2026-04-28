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
import javax.crypto.KDF;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class KdfTest {
    static final String ALG = "HKDF-SHA256";
    static final int MIN_SECURITY_STRENGTH_IN_BITS = 112;
    static final byte[] MIN_IKM = new byte[MIN_SECURITY_STRENGTH_IN_BITS / 8];

    @Test
    public void getAlgorithm() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        assertEquals(ALG, kdf.getAlgorithm());
    }

    @Test
    public void getParameters() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        assertEquals(null, kdf.getParameters());
    }

    @Test
    public void getProviderName() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        assertEquals("JipherJCE", kdf.getProviderName());
    }

    @Test
    public void minIkmLenExtractOnly() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract().addIKM(MIN_IKM).extractOnly();
        byte[] expectedDerivedData = TestUtil.hexToBytes("7AD5DD7EF851D1DF58FE0E44E805CFF07623B7ABF479C5018D0953417D8DA31A");
        assertArrayEquals(expectedDerivedData, kdf.deriveData(derivationSpec));
    }

    @Test
    public void minIkmLenExtractThenExpand() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract().addIKM(MIN_IKM).thenExpand(null, 1);
        byte[] expectedDerivedData = TestUtil.hexToBytes("53");
        assertArrayEquals(expectedDerivedData, kdf.deriveData(derivationSpec));
    }

    @Test
    public void minPrkLenHkdfSha256() throws Exception {
        byte[] expectedDerivedData = TestUtil.hexToBytes("3D7AFB663124ECBF2C953F863D4FC879");
        assertArrayEquals(expectedDerivedData, minPrkLen("HKDF-SHA256", 32));
    }

    @Test
    public void minPrkLenHkdfSha384() throws Exception {
        byte[] expectedDerivedData = TestUtil.hexToBytes("874058A2C04982C953E4A5BB4FA30FB6");
        assertArrayEquals(expectedDerivedData, minPrkLen("HKDF-SHA384", 48));
    }

    @Test
    public void minPrkLenHkdfSha512() throws Exception {
        byte[] expectedDerivedData = TestUtil.hexToBytes("3D0527D886733FC5695701B5825E5C6F");
        assertArrayEquals(expectedDerivedData, minPrkLen("HKDF-SHA512", 64));
    }

    private byte[] minPrkLen(String alg, int macLen) throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(alg);
        SecretKeySpec shortPrkKeySpec = new SecretKeySpec(new byte[macLen], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(shortPrkKeySpec, null, 16);
        return kdf.deriveData(derivationSpec);
    }

    @Test
    public void maxOkmLenHkdfSha256() throws Exception {
        maxOkmLen("HKDF-SHA256", 32);
    }

    @Test
    public void maxOkmLenHkdfSha384() throws Exception {
        maxOkmLen("HKDF-SHA384", 48);
    }

    @Test
    public void maxOkmLenHkdfSha512() throws Exception {
        maxOkmLen("HKDF-SHA512", 64);
    }

    private void maxOkmLen(String alg, int macLen) throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(alg);
        int maxOkmLen = macLen * 255;
        SecretKeySpec keySpec = new SecretKeySpec(new byte[macLen], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(keySpec, new byte[0], maxOkmLen);
        kdf.deriveData(derivationSpec);
    }
}
