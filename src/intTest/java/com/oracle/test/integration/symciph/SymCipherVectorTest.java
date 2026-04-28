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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

@RunWith(Parameterized.class)
public class SymCipherVectorTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(SymCipherTestVector.class);
    }

    private final SecretKey secretKey;
    private final String alg;
    private AlgorithmParameterSpec spec;
    private final byte[] plaintext;
    private final byte[] ciphertext;
    private final byte[] aad;

    public SymCipherVectorTest(String alg, SymCipherTestVector tv) throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().startsWith("DESEDE"));
        this.alg = alg;
        this.secretKey = new SecretKeySpec(tv.getKey(), alg.split("/")[0]);
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();
        this.aad = tv.getAad();
        SymCipherTestVector.CipherParams params = tv.getCiphParams();
        if (params != null) {
            if (alg.endsWith("GCM/NoPadding")) {
                spec = new GCMParameterSpec(params.getTagLen(), params.getIv());
            } else {
                spec = new IvParameterSpec(tv.getCiphParams().getIv());
            }
        }
    }

    @Test
    public void encryptDecrypt() throws Exception {
        Assume.assumeTrue(EnvUtil.getPolicy() == EnvUtil.FipsPolicy.NONE || !this.alg.contains("DESede"));

        Cipher encryptor = ProviderUtil.getCipher(this.alg);
        try {
            encryptor.init(Cipher.ENCRYPT_MODE, this.secretKey, spec);
            if (invalidAlgorithmParameterExceptionExpected(true)) {
                Assert.fail("InvalidAlgorithmParameterExceptionExpected");
            }
        } catch (InvalidAlgorithmParameterException e) {
            if (!invalidAlgorithmParameterExceptionExpected(true)) {
                throw e;
            }
            return;
        }
        if (aad != null) {
            encryptor.updateAAD(this.aad);
        }
        byte[] ctext = encryptor.doFinal(this.plaintext);

        doDecrypt(ctext);
    }
    @Test
    public void decrypt() throws Exception {
        try {
            doDecrypt(this.ciphertext);
        } catch (InvalidAlgorithmParameterException e) {
            if (!invalidAlgorithmParameterExceptionExpected(false)) {
                throw e;
            }
        }
    }

    void doDecrypt(byte[] cTextComputed) throws Exception {

        Cipher decryptor = ProviderUtil.getCipher(this.alg);
        decryptor.init(Cipher.DECRYPT_MODE, this.secretKey, spec);
        if (aad != null) {
            decryptor.updateAAD(this.aad);
        }
        byte[] decrypted = decryptor.doFinal(cTextComputed, 0, cTextComputed.length);
        if (!Arrays.equals(decrypted, this.plaintext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(decrypted));
            System.out.println("expected: " + TestUtil.bytesToHex(this.plaintext));
        }
        Assert.assertArrayEquals(this.plaintext, decrypted);
    }

    boolean invalidAlgorithmParameterExceptionExpected(boolean encrypt) {
        if (this.alg.toUpperCase().contains("GCM") && this.spec instanceof GCMParameterSpec) {
            int ivLen = ((GCMParameterSpec) this.spec).getIV().length;
            if (encrypt) {
                // FIPS 140-3 requires the GCM nonce (IV) to be generated within the FIPS boundary when
                // encrypting. See SP 800-38D section 9.1 'Design considerations' & FIPS 140-3
                // implementation guidance section C.H 'Key/IV Pair Uniqueness Requirements from SP 800-38D'.
                // However, the SunJSSE provider imports 96-bit and 128-bit IVs for GCM encryption and thus
                // Jipher permits IVs with at least 96-bits to be imported for GCM encryption.
                return ivLen < 12;
            }
        }
        return false;
    }
}
