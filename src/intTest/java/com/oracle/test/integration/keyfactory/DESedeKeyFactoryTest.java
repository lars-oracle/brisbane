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

package com.oracle.test.integration.keyfactory;

import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.DESKeySpec;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class DESedeKeyFactoryTest {

    public DESedeKeyFactoryTest() {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported());
    }

    SecretKeyFactory skf;

    byte[] testKey = hexStringToByteArray("444444444444444444444444444444444444444444444444");
    byte[] testKeyParity = hexStringToByteArray("454545454545454545454545454545454545454545454545");

    @Before
    public void setUp() throws Exception {
        skf = ProviderUtil.getSecretKeyFactory("DESede");
    }

    @Test
    public void generateSecretSecretKeySpec() throws Exception {
        SecretKey key = skf.generateSecret(new SecretKeySpec(testKey, "DESede"));
        checkKey(key, testKeyParity);
    }
    @Test
    public void generateSecretDESedeKeySpec() throws Exception {
        SecretKey key = skf.generateSecret(new DESedeKeySpec(testKey));
        checkKey(key, testKeyParity);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateSecretInvalidLength() throws Exception {
        SecretKey key = skf.generateSecret(new SecretKeySpec(hexStringToByteArray("00112233445566778899aabbccddee"), "DESede"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateSecretInvalidSpec() throws Exception {
        SecretKey key = skf.generateSecret(new DESKeySpec(hexStringToByteArray("00112233445566778899aabbccddeeff001122334455667788")));
    }

    void checkKey(SecretKey key, byte[] bytes) throws Exception {
        assertArrayEquals(bytes, key.getEncoded());
        assertTrue(DESedeKeySpec.isParityAdjusted(key.getEncoded(), 0));
        assertEquals("DESede", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
    }

    @Test
    public void getKeySpecSecretKeySpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", testKey, "RAW"), SecretKeySpec.class);
        assertTrue(spec instanceof SecretKeySpec);
        assertArrayEquals(testKey, ((SecretKeySpec) spec).getEncoded());
        assertEquals("DESede", ((SecretKeySpec) spec).getAlgorithm());
    }

    @Test
    public void getKeySpecDESedeKeySpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", testKey, "RAW"), DESedeKeySpec.class);
        assertTrue(spec instanceof DESedeKeySpec);

        assertArrayEquals(testKey, ((DESedeKeySpec) spec).getKey());
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadSpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", testKey, "RAW"), DESKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyAlg() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("FFF", testKey, "RAW"), DESedeKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyFormat() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", testKey, "Full"), DESedeKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyLength() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", new byte[23], "RAW"), DESedeKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyAlgSecretKeySpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("FFF", testKey, "RAW"), SecretKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyFormatSecretKeySpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", testKey, "Full"), SecretKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadKeyLengthSecretKeySpec() throws Exception {
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("DESede", new byte[23], "RAW"), SecretKeySpec.class);
    }

    @Test
    public void translateKey() throws Exception {
        SecretKey skey = skf.translateKey(KeyUtil.getDummySecretKey("DESede", testKey, "RAW"));
        checkKey(skey, testKeyParity);
    }


    @Test(expected = InvalidKeyException.class)
    public void translateKeyInvalidLength() throws Exception {
        byte[] invalidKey = hexStringToByteArray("00112233445566778899");
        SecretKey skey = skf.translateKey(KeyUtil.getDummySecretKey("DESede", invalidKey, "RAW"));
    }
}
