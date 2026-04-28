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

package com.oracle.test.integration.asymciph;

import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class AsymCipherVectorTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(AsymCipherTestVector.class);
    }

    private final String alg;
    private final PublicKey pub;
    private final PrivateKey priv;
    private final byte[] plaintext;
    private final byte[] ciphertext;
    private Cipher cipher;
    private AlgorithmParameterSpec spec;

    public AsymCipherVectorTest(String alg, AsymCipherTestVector tv) throws Exception {
        this.alg = alg;
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId()));
        this.pub = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
        this.priv = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();
        if (tv.getParams() != null) {
            AsymCipherTestVector.AsymParams params = tv.getParams();
            this.spec = new OAEPParameterSpec(getAlgMd(), "MGF1", new MGF1ParameterSpec(params.mgfAlg()),
                    params.psourceVal() == null ? PSource.PSpecified.DEFAULT : new PSource.PSpecified(params.psourceVal()));
        }
    }

    private String getAlgMd() {
        int index = this.alg.indexOf("OAEP");
        if (index == -1) {
            return null;
        }
        return this.alg.substring(index +8, this.alg.indexOf("andMGF1"));
    }

    @Before
    public void before() throws Exception {
        this.cipher = ProviderUtil.getCipher(this.alg);
    }

    @Test
    public void encryptDecrypt() throws Exception {
        cipher.init(Cipher.ENCRYPT_MODE, this.pub, this.spec);
        cipher.update(this.plaintext);
        byte[] ctext = cipher.doFinal();

        doDecrypt(ctext);
    }

    @Test
    public void decrypt() throws Exception {
        if (alg.contains("OAEPWithSHA") && !alg.contains("OAEPWithSHA-1")) {
            // OpenSSL FIPS providers before version 3.0.7 have a bug decrypting OAEP with a digest other than SHA-1
            Assume.assumeTrue(FipsProviderInfoUtil.getMajorVersion() > 3 ||
                    FipsProviderInfoUtil.getMinorVersion() > 0 || FipsProviderInfoUtil.getPatchVersion() >= 7);
        }
        doDecrypt(this.ciphertext);
    }

    void doDecrypt(byte[] cTextComputed) throws Exception {
        Cipher cipher = ProviderUtil.getCipher(this.alg);
        cipher.init(Cipher.DECRYPT_MODE, this.priv, this.spec);
        cipher.update(cTextComputed, 0, cTextComputed.length);

        byte[] decrypted = cipher.doFinal();
        Assert.assertArrayEquals(this.plaintext, decrypted);
    }

    @Test
    public void wrapUnwrap() throws Exception {
        cipher.init(Cipher.WRAP_MODE, this.pub, this.spec);
        byte[] ctext = cipher.wrap(new SecretKeySpec(this.plaintext, ""));
        doUnwrap(ctext);
    }

    @Test
    public void unwrap() throws Exception {
        if (alg.contains("OAEPWithSHA") && !alg.contains("OAEPWithSHA-1")) {
            // OpenSSL FIPS provider versions before 3.0.7 have a bug decrypting OAEP with a digest other than SHA-1
            Assume.assumeTrue(FipsProviderInfoUtil.getMajorVersion() > 3 ||
                    FipsProviderInfoUtil.getMinorVersion() > 0 || FipsProviderInfoUtil.getPatchVersion() >= 7);
        }
        doUnwrap(this.ciphertext);
    }

    void doUnwrap(byte[] cTextComputed) throws Exception {
        Cipher cipher = ProviderUtil.getCipher(this.alg);
        cipher.init(Cipher.UNWRAP_MODE, this.priv, this.spec);
        Key key = cipher.unwrap(cTextComputed, "FOO", Cipher.SECRET_KEY);
        assertTrue(key instanceof SecretKey);
        assertEquals("FOO", key.getAlgorithm());

        byte[] decrypted = key.getEncoded();
        Assert.assertArrayEquals(this.plaintext, decrypted);
    }
}
