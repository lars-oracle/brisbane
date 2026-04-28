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

import java.nio.charset.StandardCharsets;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotSame;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class PbeKeyFactoryTest {

    static final String ALGORITHM = "PBEWithHmacSHA1AndAES_128";
    static final String FORMAT = "RAW";
    static final char[] PASSWORD_CHARS = "password".toCharArray();
    static final byte[] PASSWORD_ENCODED = "password".getBytes(StandardCharsets.UTF_8);
    static final byte[] PASSWORD_ENCODED_HIGH_BIT_SET = hexStringToByteArray("f06173f3776f7264");
    static final byte[] SALT = hexStringToByteArray("73616C74");
    static final int ITER = 1;
    static final int KEYLEN = 128;
    static final char[] EMPTY_CHARS = {};
    static final byte[] EMPTY_BYTES = {};
    static final char[] UNICODE_CHARS = "coffee\u2615".toCharArray();
    static final byte[] UNICODE_ENCODED = "coffee\u2615".getBytes(StandardCharsets.UTF_8);
    static final char[] CTRL_CHARS = "\u0007\u0009".toCharArray();
    static final byte[] CTRL_ENCODED = "\u0007\u0009".getBytes(StandardCharsets.UTF_8);
    static final String[] ALG_NAMES = {
        "PBEWithHmacSHA1AndAES_128",
        "PBEWithHmacSHA224AndAES_128",
        "PBEWithHmacSHA256AndAES_128",
        "PBEWithHmacSHA384AndAES_128",
        "PBEWithHmacSHA512AndAES_128",
        "PBEWithHmacSHA1AndAES_256",
        "PBEWithHmacSHA224AndAES_256",
        "PBEWithHmacSHA256AndAES_256",
        "PBEWithHmacSHA384AndAES_256",
        "PBEWithHmacSHA512AndAES_256"
    };

    SecretKeyFactory skf;

    @Before
    public void setUp() throws Exception {
        skf = ProviderUtil.getSecretKeyFactory(ALGORITHM);
    }

    @Test
    public void generateSecret() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key);
        assertNotSame(key.getEncoded(), key.getEncoded());
    }

    @Test
    public void generateSecretAlgs() throws Exception {
        for (String alg: ALG_NAMES) {
            SecretKeyFactory askf = ProviderUtil.getSecretKeyFactory(alg);
            PBEKeySpec ks = new PBEKeySpec(PASSWORD_CHARS);
            SecretKey key = askf.generateSecret(ks);
            assertEquals(alg, key.getAlgorithm());
            assertArrayEquals(PASSWORD_ENCODED, key.getEncoded());
            assertEquals(FORMAT, key.getFormat());
            assertFalse(key instanceof PBEKey);
            assertFalse(key instanceof SecretKeySpec);
        }
    }

    @Test
    public void equalsAndHashCode() throws Exception {
        PBEKeySpec ks0 = new PBEKeySpec(PASSWORD_CHARS);
        SecretKey key0 = skf.generateSecret(ks0);
        SecretKey key1 = skf.generateSecret(ks0);
        PBEKeySpec ks1 = new PBEKeySpec("Different password".toCharArray());
        SecretKey key2 = skf.generateSecret(ks1);
        SecretKeyFactory skf0 = ProviderUtil.getSecretKeyFactory("PBEWithHmacSHA256AndAES_128");
        SecretKey key3 = skf0.generateSecret(ks0);

        // Test equals()
        assertTrue(key0.equals(key1));
        assertTrue(key1.equals(key0));
        assertFalse(key1.equals(key2));
        assertFalse(key2.equals(key1));
        assertFalse(key2.equals(key3));
        assertFalse(key3.equals(key2));
        assertFalse(key1.equals(key3));
        assertFalse(key3.equals(key1));

        // Different class
        assertFalse(key0.equals(ks0));

        // Test hashCode()
        assertEquals(key0.hashCode(), key1.hashCode());

        // destroy() one key then equals()
        key0.destroy();
        assertFalse(key0.equals(key1));
        assertFalse(key1.equals(key0));

        // destroy() both keys then equals() and hashCode()
        key1.destroy();
        assertTrue(key0.equals(key1));
        assertTrue(key1.equals(key0));
        assertEquals(key0.hashCode(), key1.hashCode());
    }

    @Test
    public void generateSecretEmptyPassword() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(EMPTY_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key, EMPTY_BYTES);
    }

    @Test
    public void generateSecretDestroyKey() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key);

        Destroyable d = key;
        assertFalse(d.isDestroyed());
        d.destroy();
        assertTrue(d.isDestroyed());

        assertEquals(ALGORITHM, key.getAlgorithm());
        assertEquals(FORMAT, key.getFormat());
    }

    @Test
    public void generateSecretIgnoreExtraParams() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_CHARS, SALT, ITER, KEYLEN);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key);
    }

    @Test
    public void generateSecretCtrlChars() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(CTRL_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key, CTRL_ENCODED);
    }

    @Test
    public void generateSecretUnicodeChars() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(UNICODE_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key, UNICODE_ENCODED);
    }

    @Test(expected=IllegalStateException.class)
    public void generateSecretDestroyKeyGetEncoded() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_CHARS);
        SecretKey key = skf.generateSecret(ks);
        checkPasswordKey(key);
        key.destroy();
        byte[] dk = key.getEncoded();
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecNull() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        skf.getKeySpec(key, null);
    }

    @Test
    public void getKeySpecFromSecretKeySpec() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        KeySpec ks = skf.getKeySpec(key, KeySpec.class);
        assert(ks instanceof PBEKeySpec);
        checkPBEKeySpec((PBEKeySpec) ks);
    }

    @Test
    public void getPBEKeySpecFromSecretKeySpec() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecFromPBEKey() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, null, null, 0);
        KeySpec ks = skf.getKeySpec(key, KeySpec.class);
        assert(ks instanceof PBEKeySpec);
        checkPBEKeySpec((PBEKeySpec) ks);
    }

    @Test
    public void getPBEKeySpecFromPBEKey() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, null, null, 0);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecDifferentAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBEWithHmacSHA256AndAES_256");
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecDifferentAlgorithmUpper() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBEWITHHMACSHA256ANDAES_256");
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecRoundTrip() throws Exception {
        PBEKeySpec ks1 = new PBEKeySpec(PASSWORD_CHARS);
        checkPBEKeySpec(ks1);
        SecretKey key = skf.generateSecret(ks1);

        PBEKeySpec ks2 = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks2);
    }

    @Test
    public void getKeySpecFromPBEKeyWithExtraParams() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, PASSWORD_CHARS, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecFromPBEKeyIgnoreExtraParams() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, UNICODE_CHARS, EMPTY_BYTES, -1);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecFromPBEKeySpecEmptyPassword() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, EMPTY_BYTES, FORMAT, null, null, 0);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks, EMPTY_CHARS);
    }

    @Test
    public void getKeySpecFromSecretKeySpecHighBitSet() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED_HIGH_BIT_SET, ALGORITHM);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getKeySpecFromSecretKeySpecCtrlChars() throws Exception {
        SecretKey key = new SecretKeySpec(CTRL_ENCODED, ALGORITHM);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks, CTRL_CHARS);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void getKeySpecNullPassword() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, null, FORMAT, null, null, 0);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key format/algorithm
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecShortAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBE");
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key format/algorithm
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecWrongAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "ZZZ");
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key format/algorithm
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecWrongFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, "ASN.1", null, null, 0);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
    }

    @Test
    public void translateKeyFromSecretKeySpec() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyFromPBEKeySpecEmptyPassword() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, EMPTY_BYTES, FORMAT, null, null, 0);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey, EMPTY_BYTES);
    }

    @Test
    public void translateKeyDestroyKey() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);

        Destroyable d = pwKey;
        assertFalse(d.isDestroyed());
        d.destroy();
        assertTrue(d.isDestroyed());

        assertEquals(ALGORITHM, key.getAlgorithm());
        assertEquals(FORMAT, key.getFormat());
    }

    @Test
    public void translateKeyFromPBEKey() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, null, null, 0);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyDifferentAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBEWithHmacSHA256AndAES_256");
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyDifferentAlgorithmUpper() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBEWITHHMACSHA256ANDAES_256");
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyFromPBEKeyWithExtraParams() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, PASSWORD_CHARS, SALT, ITER);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyFromPBEKeyIgnoreExtraParams() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, FORMAT, UNICODE_CHARS, EMPTY_BYTES, -1);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
    }

    @Test
    public void translateKeyFromSecretKeySpecCtrlChars() throws Exception {
        SecretKey key = new SecretKeySpec(CTRL_ENCODED, ALGORITHM);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey, CTRL_ENCODED);
    }

    // java.security.spec.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyShortAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "PBE");
        SecretKey pwKey = skf.translateKey(key);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void translateKeyNullPassword() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, null, FORMAT, null, null, 0);
        SecretKey pwKey = skf.translateKey(key);
    }

    // java.security.spec.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyWrongAlgorithm() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, "ZZZ");
        SecretKey pwKey = skf.translateKey(key);
    }

    // java.security.spec.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyWrongFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, PASSWORD_ENCODED, "ASN.1", null, null, 0);
        SecretKey pwKey = skf.translateKey(key);
    }

    @Test(expected=IllegalStateException.class)
    public void translateKeyDestroyKeyGetEncoded() throws Exception {
        SecretKey key = new SecretKeySpec(PASSWORD_ENCODED, ALGORITHM);
        SecretKey pwKey = skf.translateKey(key);
        checkPasswordKey(pwKey);
        pwKey.destroy();
        byte[] encoded = pwKey.getEncoded();
    }

    private void checkPBEKeySpec(PBEKeySpec ks) throws Exception {
        checkPBEKeySpec(ks, PASSWORD_CHARS);
    }

    private void checkPBEKeySpec(PBEKeySpec ks, char[] pw) throws Exception {
        assertArrayEquals(pw, ks.getPassword());
        assertNull(ks.getSalt());
        assertEquals(0, ks.getIterationCount());
        assertEquals(0, ks.getKeyLength());
    }

    private void checkPasswordKey(SecretKey key) throws Exception {
        checkPasswordKey(key, PASSWORD_ENCODED);
    }

    private void checkPasswordKey(SecretKey key, byte[] pw) throws Exception {
        checkPasswordKey(key, pw, ALGORITHM);
    }

    private void checkPasswordKey(SecretKey key, byte[] pw, String alg) throws Exception {
        assertEquals(alg, key.getAlgorithm());
        assertArrayEquals(pw, key.getEncoded());
        assertEquals(FORMAT, key.getFormat());
        assertNotSame(key.getEncoded(), key.getEncoded());
        assertFalse(key instanceof PBEKey);
        assertFalse(key instanceof SecretKeySpec);
    }

}
