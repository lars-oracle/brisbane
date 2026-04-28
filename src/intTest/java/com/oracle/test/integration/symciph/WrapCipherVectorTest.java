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

import java.security.Key;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.testdata.WrapCipherTestVector;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class WrapCipherVectorTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(WrapCipherTestVector.class);
    }

    private final SecretKey secretKey;
    private String alg;
    private final byte[] plaintext;
    private final byte[] ciphertext;

    public WrapCipherVectorTest(String alg, WrapCipherTestVector tv) throws Exception {
        this.alg = alg;
        this.secretKey = new SecretKeySpec(tv.getKey(), alg.split("/")[0]);
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();
    }

    @Test
    public void wrapUnwrap() throws Exception {
        byte[] ctext = doWrap();
        Cipher encryptor = ProviderUtil.getCipher(this.alg);
        encryptor.init(Cipher.WRAP_MODE, this.secretKey);
        assertArrayEquals(this.ciphertext, ctext);
        doUnwrap(ctext);
    }

    @Test
    public void unwrap() throws Exception {
        doUnwrap(this.ciphertext);
    }

    @Test
    public void wrapFixedSizeAlg() throws Exception {
        this.alg += "_" + (this.secretKey.getEncoded().length * 8);
        byte[] ctext = doWrap();
        if (!Arrays.equals(this.ciphertext,ctext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(this.ciphertext));
            System.out.println("expected: " + TestUtil.bytesToHex(ctext));
        }
        assertArrayEquals(this.ciphertext, ctext);
    }

    byte[] doWrap() throws Exception {
        Cipher encryptor = ProviderUtil.getCipher(this.alg);
        encryptor.init(Cipher.WRAP_MODE, this.secretKey);
        return encryptor.wrap(new SecretKeySpec(this.plaintext, "Key"));
    }

    void doUnwrap(byte[] cTextComputed) throws Exception {
        Cipher decryptor = ProviderUtil.getCipher(this.alg);
        decryptor.init(Cipher.UNWRAP_MODE, this.secretKey);
        Key unwrapped = decryptor.unwrap(cTextComputed, "blah", Cipher.SECRET_KEY);
        if (!Arrays.equals(unwrapped.getEncoded(), this.plaintext)) {
            System.out.println("was:      " + TestUtil.bytesToHex(unwrapped.getEncoded()));
            System.out.println("expected: " + TestUtil.bytesToHex(this.plaintext));
        }
        assertArrayEquals(this.plaintext, unwrapped.getEncoded());
    }
}
