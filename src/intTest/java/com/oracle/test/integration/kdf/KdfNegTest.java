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

import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KDF;
import javax.crypto.KDFParameters;
import javax.crypto.spec.HKDFParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

public class KdfNegTest {
    static final String ALG = "HKDF-SHA256";
    static final int MIN_SECURITY_STRENGTH_IN_BITS = 112;
    static final byte[] INSUFFICIENT_IKM = new byte[MIN_SECURITY_STRENGTH_IN_BITS / 8 - 1];

    static class DummyKDFParameters implements KDFParameters {
        DummyKDFParameters() {}
    }

    DummyKDFParameters KDF_PARAMETERS = new DummyKDFParameters();

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void kdfParamsNeg() throws Exception {
        ProviderUtil.getKdf(ALG, KDF_PARAMETERS);
    }

    @Test(expected = NullPointerException.class)
    public void kdfDeriveKeyNullAlgNeg() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[32], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(null, new byte[0], 32);
        kdf.deriveKey(null, derivationSpec);
    }

    @Test(expected = NoSuchAlgorithmException.class)
    public void kdfDeriveKeyEmptyAlgNeg() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        SecretKeySpec keySpec = new SecretKeySpec(new byte[32], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(keySpec, new byte[0], 32);
        kdf.deriveKey("", derivationSpec);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void insufficientIkmExtractOnly() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract().addIKM(INSUFFICIENT_IKM).extractOnly();
        kdf.deriveData(derivationSpec);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void insufficientIkmExtractThenExpand() throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(ALG);
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.ofExtract().addIKM(INSUFFICIENT_IKM).thenExpand(null, 1);
        kdf.deriveData(derivationSpec);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void prkLenTooSmallHkdfSha256Neg() throws Exception {
        prkLenTooSmall("HKDF-SHA256", 32);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void prkLenTooSmallHkdfSha384Neg() throws Exception {
        prkLenTooSmall("HKDF-SHA384", 48);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void prkLenTooSmallHkdfSha512Neg() throws Exception {
        prkLenTooSmall("HKDF-SHA512", 64);
    }

    private void prkLenTooSmall(String alg, int macLen) throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(alg);
        SecretKeySpec shortPrkKeySpec = new SecretKeySpec(new byte[macLen - 1], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(shortPrkKeySpec, null, 16);

        kdf.deriveData(derivationSpec);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void okmLenTooLargeHkdfSha256Neg() throws Exception {
        okmLenTooLarge("HKDF-SHA256", 32);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void okmLenTooLargeHkdfSha384Neg() throws Exception {
        okmLenTooLarge("HKDF-SHA384", 48);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void okmLenTooLargeHkdfSha512Neg() throws Exception {
        okmLenTooLarge("HKDF-SHA512", 64);
    }

    private void okmLenTooLarge(String alg, int macLen) throws Exception {
        KDF kdf = (KDF) ProviderUtil.getKdf(alg);
        int maxOkmLen = macLen * 255;
        SecretKeySpec keySpec = new SecretKeySpec(new byte[macLen], "generic");
        AlgorithmParameterSpec derivationSpec = HKDFParameterSpec.expandOnly(keySpec, new byte[0], maxOkmLen + 1);

        kdf.deriveData(derivationSpec);
    }
}
