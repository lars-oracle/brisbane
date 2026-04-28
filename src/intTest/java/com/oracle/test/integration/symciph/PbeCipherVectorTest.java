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
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.PBEParameterSpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.PbeCipherTestVector;
import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

@RunWith(Parameterized.class)
public class PbeCipherVectorTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(PbeCipherTestVector.class);
    }

    private final char[] password;
    private final String alg;
    private final AlgorithmParameterSpec spec;
    private final byte[] plaintext;
    private final byte[] ciphertext;

    public PbeCipherVectorTest(String alg, PbeCipherTestVector tv) throws Exception {
        this.alg = alg;
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();

        SymCipherTestVector.CipherParams cParams = tv.getCiphParams();
        AlgorithmParameterSpec ivPSpec = null;
        if (cParams != null) {
            ivPSpec = new IvParameterSpec(cParams.getIv());
        }

        PbeCipherTestVector.PbeParams pParams = tv.getPbeParams();
        this.password = pParams.getPassword();
        this.spec = new PBEParameterSpec(pParams.getSalt(), pParams.getIterationCount(), ivPSpec);
    }

    @Test
    public void encryptDecrypt() throws Exception {
        SecretKeyFactory skf = ProviderUtil.getSecretKeyFactory(this.alg);
        SecretKey secretKey = skf.generateSecret(new PBEKeySpec(this.password));

        Cipher encryptor = ProviderUtil.getCipher(this.alg);
        encryptor.init(Cipher.ENCRYPT_MODE, secretKey, this.spec);
        byte[] ctext = encryptor.doFinal(this.plaintext);

        doDecrypt(ctext);
    }

    @Test
    public void decrypt() throws Exception {
        doDecrypt(this.ciphertext);
    }

    void doDecrypt(byte[] cTextComputed) throws Exception {
        SecretKeyFactory skf = ProviderUtil.getSecretKeyFactory(this.alg);
        SecretKey secretKey = skf.generateSecret(new PBEKeySpec(this.password));

        Cipher decryptor = ProviderUtil.getCipher(this.alg);
        decryptor.init(Cipher.DECRYPT_MODE, secretKey, this.spec);
        byte[] decrypted = decryptor.doFinal(cTextComputed, 0, cTextComputed.length);
        if (!Arrays.equals(decrypted, this.plaintext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(decrypted));
            System.out.println("expected: " + TestUtil.bytesToHex(this.plaintext));
        }
        Assert.assertArrayEquals(this.plaintext, decrypted);
    }
}
