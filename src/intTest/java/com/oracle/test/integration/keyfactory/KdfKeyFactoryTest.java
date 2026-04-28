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
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.crypto.spec.SecretKeySpec;
import javax.security.auth.Destroyable;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;

public class KdfKeyFactoryTest {

    static final int MIN_SECURITY_STRENGTH = 112; //bits

    static final String ALGORITHM = "PBKDF2WithHmacSHA1";
    static final String FORMAT = "RAW";
    static final char[] PASSWORD = "password".toCharArray();
    static final byte[] SALT = hexStringToByteArray("00112233445566778899AABBCCDDEEFF");
    static final int ITER = 1000;
    static final byte[] DK = hexStringToByteArray("5AE4359FD9E7289DDA2A28E3745F519839DDD0C0");
    static final byte[] DK_EMPTY_PW = hexStringToByteArray("529C87CD9D7D4DC2FF80E58B84CBF9CD");


    static final char[] EMPTY_CHARS = {};
    static final byte[] EMPTY_BYTES = {};

    static final char[] PASSWORD_COFFEE = "coffee-\u2615".toCharArray();
    static final byte[] DK_COFFEE = hexStringToByteArray("E54865411B4808127BAF694F4D7585E7FCF596ADA495CD82CBDFF7F00FC72F14");
    static final byte[] DK_COFFEE_8BIT = hexStringToByteArray("42866C688A5549AE6BB6BDBCFC100ABCA11798E63ED93864DEFA6ED1D429715B");

    SecretKeyFactory skf;

    @Before
    public void setUp() throws Exception {
        skf = ProviderUtil.getSecretKeyFactory(ALGORITHM);
    }

    @Test
    public void generateSecret() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        checkPBEKey(key);
    }

    @Test
    public void generateSecretMinKeyLen() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        byte[] dk = Arrays.copyOf(DK, MIN_SECURITY_STRENGTH / 8);
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, dk.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        checkPBEKey(key, dk);
    }

    @Test
    public void equalsAndHashCode() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks0 = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        SecretKey key0 = skf.generateSecret(ks0);
        SecretKey key1 = skf.generateSecret(ks0);
        PBEKeySpec ks1 = new PBEKeySpec("Different password".toCharArray(), SALT, ITER, DK.length * 8);
        SecretKey key2 = skf.generateSecret(ks1);
        SecretKeyFactory skf0 = ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA256");
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
    public void generateSecretUnicode() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD_COFFEE));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD_COFFEE));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_COFFEE, SALT, ITER, DK_COFFEE.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        checkPBEKey(key, DK_COFFEE, PASSWORD_COFFEE);
    }

    @Test
    public void generateSecret8BitNonAsciiPasswd() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= get8BitLen(PASSWORD_COFFEE));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= get8BitLen(PASSWORD_COFFEE));
        SecretKeyFactory skf0 = ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA1and8BIT");
        PBEKeySpec ks = new PBEKeySpec(PASSWORD_COFFEE, SALT, ITER, DK_COFFEE_8BIT.length * 8);
        PBEKey key = (PBEKey) skf0.generateSecret(ks);
        checkPBEKey(key, DK_COFFEE_8BIT, PASSWORD_COFFEE, "PBKDF2WithHmacSHA1and8BIT");
    }

    @Test
    public void generateSecret8BitAsciiPasswd() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= get8BitLen(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= get8BitLen(PASSWORD));
        SecretKeyFactory skf0 = ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA1and8BIT");
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf0.generateSecret(ks);
        checkPBEKey(key, DK, PASSWORD, "PBKDF2WithHmacSHA1and8BIT");
    }

    @Test
    public void generateSecretClearPasswordAfterGen() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        ks.clearPassword();
        checkPBEKey(key);
    }

    @Test
    public void generateSecretEmptyPassword() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() == 0);
        PBEKeySpec ks = new PBEKeySpec(EMPTY_CHARS, SALT, ITER, DK_EMPTY_PW.length * 8);
        try {
            PBEKey key = (PBEKey) skf.generateSecret(ks);
            Assert.assertEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
            checkPBEKey(key, DK_EMPTY_PW, EMPTY_CHARS);
        } catch (InvalidKeySpecException e) {
            Assert.assertNotEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
        }
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateSecretShortPassword() throws Exception {
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() != 0);

        PBEKeySpec ks = new PBEKeySpec(new char[EnvUtil.getMinPbkdf2PasswordLength() -1], SALT, ITER, DK_EMPTY_PW.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
    }

    @Test
    public void generateSecretDestroyKey() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        checkPBEKey(key);

        Destroyable d = key;
        assertFalse(d.isDestroyed());
        d.destroy();
        assertTrue(d.isDestroyed());

        assertArrayEquals(SALT, key.getSalt());
        assertEquals(ITER, key.getIterationCount());
        assertEquals(ALGORITHM, key.getAlgorithm());
        assertEquals(FORMAT, key.getFormat());
    }

    @Test
    public void getKeySpec() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, KeySpec.class);
        assert(ks instanceof PBEKeySpec);
        checkPBEKeySpec((PBEKeySpec)ks);
    }

    @Test
    public void getPBEKeySpec() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getPBEKeySpecNull() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, null, SALT, ITER);
        skf.getKeySpec(key, null);
    }

    @Test
    public void getPBEKeySpecNullPassword() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() == 0);
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() == 0);

        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, null, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks, EMPTY_CHARS);
    }

    @Test
    public void getPBEKeySpecEmptyPassword() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, EMPTY_CHARS, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks, EMPTY_CHARS);
    }

    @Test
    public void getPBEKeySpecNullAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(null, DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecInvalidAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("INVALID", DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecShortAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("PBKDF2", DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecAltAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("PBKDF2WithHmacSHA256", DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecNullFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, null, PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecEmptyFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, "", PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void getPBEKeySpecAltFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, "ASN.1", PASSWORD, SALT, ITER);
        PBEKeySpec ks = (PBEKeySpec)skf.getKeySpec(key, PBEKeySpec.class);
        checkPBEKeySpec(ks);
    }

    @Test
    public void translateKey() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        PBEKey pbeKey = (PBEKey)skf.translateKey(key);
        checkPBEKey(pbeKey);
    }

    @Test
    public void translateKeyNullPassword() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() == 0);
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK_EMPTY_PW, FORMAT, null, SALT, ITER);
        try {
            PBEKey pbeKey = (PBEKey) skf.translateKey(key);
            Assert.assertEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
            checkPBEKey(pbeKey, DK_EMPTY_PW, EMPTY_CHARS);
        } catch (InvalidKeyException e) {
            Assert.assertNotEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
        }
    }

    @Test
    public void translateKeyEmptyPassword() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() == 0);
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK_EMPTY_PW, FORMAT, EMPTY_CHARS, SALT, ITER);
        try {
            PBEKey pbeKey = (PBEKey) skf.translateKey(key);
            Assert.assertEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
            checkPBEKey(pbeKey, DK_EMPTY_PW, EMPTY_CHARS);
        } catch (InvalidKeyException e) {
            Assert.assertNotEquals(0, EnvUtil.getMinPbkdf2PasswordLength());
        }
    }

    // java.security.spec.InvalidKeySpecException: Invalid key spec
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretNullKeySpec() throws Exception {
        SecretKey key = skf.generateSecret(null);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key spec
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretSecretKeySpec() throws Exception {
        KeySpec ks = new SecretKeySpec(DK, ALGORITHM);
        SecretKey key = skf.generateSecret(ks);
    }

    // java.lang.IllegalStateException: password has been cleared
    @Test(expected=IllegalStateException.class)
    public void generateSecretPasswordCleared() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        ks.clearPassword();
        SecretKey key = skf.generateSecret(ks);
    }

    // java.security.spec.InvalidKeySpecException: Key length not found
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretNoKeyLength() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER);
        SecretKey key = skf.generateSecret(ks);
    }

    // java.security.spec.InvalidKeySpecException: Salt not found
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretNoSalt() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD);
        SecretKey key = skf.generateSecret(ks);
    }

    // java.security.spec.InvalidKeySpecException: Salt must be at least 16 bytes
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretShortSalt() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, new byte[15], ITER, DK.length * 8);
        SecretKey key = skf.generateSecret(ks);
    }

    // java.security.spec.InvalidKeySpecException: IterationCount must be at least 1000
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretInsufficientIterationCount() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER - 1, DK.length * 8);
        SecretKey key = skf.generateSecret(ks);
    }

    // java.security.spec.InvalidKeySpecException: Failed to derive key
    // Caused by: java.security.InvalidAlgorithmParameterException: iterationCount (10000001) exceeds upper bound (10000000) applied for PBKDF2
    @Test(expected=InvalidKeySpecException.class)
    public void generateSecretExcessiveIterationCount() throws Exception {
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, 10_000_001, DK.length * 8);
        SecretKey key = skf.generateSecret(ks);
    }

    @Test(expected=IllegalStateException.class)
    public void generateSecretDestroyKeyGetPassword() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        assertArrayEquals(DK, key.getEncoded());
        assertArrayEquals(PASSWORD, key.getPassword());
        key.destroy();
        char[] pw = key.getPassword();
    }

    @Test(expected=IllegalStateException.class)
    public void generateSecretDestroyKeyGetEncoded() throws Exception {
        Assume.assumeTrue(FipsProviderInfoUtil.getKDFMinPwdLen() <= getUtf8Len(PASSWORD));
        Assume.assumeTrue(EnvUtil.getMinPbkdf2PasswordLength() <= getUtf8Len(PASSWORD));
        PBEKeySpec ks = new PBEKeySpec(PASSWORD, SALT, ITER, DK.length * 8);
        PBEKey key = (PBEKey) skf.generateSecret(ks);
        assertArrayEquals(DK, key.getEncoded());
        assertArrayEquals(PASSWORD, key.getPassword());
        key.destroy();
        byte[] dk = key.getEncoded();
    }

    // java.security.spec.InvalidKeySpecException: Invalid key format/algorithm
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecNullKey() throws Exception {
        KeySpec ks = skf.getKeySpec(null, PBEKeySpec.class);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key format/algorithm
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecSecretKeySpec() throws Exception {
        SecretKey key = new SecretKeySpec(DK, ALGORITHM);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key spec
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecNullKeySpec() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, null);
    }

    // java.security.spec.InvalidKeySpecException: Invalid key spec
    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecInvalidKeySpec() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, String.class);
    }

    @Test
    public void getKeySpecInterfaceKeySpec() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, KeySpec.class);
        assert(ks instanceof PBEKeySpec);
        checkPBEKeySpec((PBEKeySpec)ks);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void getKeySpecNullKeyData() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, null, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.lang.IllegalArgumentException: invalid keyLength value
    @Test(expected=IllegalArgumentException.class)
    public void getKeySpecEmptyKeyData() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, EMPTY_BYTES, FORMAT, PASSWORD, SALT, ITER);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.lang.NullPointerException: the salt parameter must be non-null
    @Test(expected=NullPointerException.class)
    public void getKeySpecNullSalt() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, null, ITER);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.lang.IllegalArgumentException: the salt parameter must not be empty
    @Test(expected=IllegalArgumentException.class)
    public void getKeySpecEmptySalt() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, EMPTY_BYTES, ITER);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.lang.IllegalArgumentException: invalid iterationCount value
    @Test(expected=IllegalArgumentException.class)
    public void getKeySpecZeroIterCount() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, 0);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.lang.IllegalArgumentException: invalid iterationCount value
    @Test(expected=IllegalArgumentException.class)
    public void getKeySpecNegativeIterCount() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, -1);
        KeySpec ks = skf.getKeySpec(key, PBEKeySpec.class);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyNullKey() throws Exception {
        SecretKey pbeKey = skf.translateKey(null);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeySecretKeySpec() throws Exception {
        SecretKey key = new SecretKeySpec(DK, ALGORITHM);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void translateKeyNullAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(null, DK, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyInvalidAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("INVALID", DK, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyShortAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("PBKDF2", DK, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyAltAlgorithm() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey("PBKDF2WithHmacSHA256", DK, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void translateKeyNullKeyData() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, null, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.IllegalArgumentException: invalid keyLength value
    @Test(expected=IllegalArgumentException.class)
    public void translateKeyEmptyKeyData() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, EMPTY_BYTES, FORMAT, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.NullPointerException
    @Test(expected=NullPointerException.class)
    public void translateKeyNullFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, null, PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyEmptyFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, "", PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.security.InvalidKeyException: Invalid key format/algorithm
    @Test(expected=InvalidKeyException.class)
    public void translateKeyBadFormat() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, "ASN.1", PASSWORD, SALT, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.NullPointerException: the salt parameter must be non-null
    @Test(expected=NullPointerException.class)
    public void translateKeyNullSalt() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, null, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.IllegalArgumentException: the salt parameter must not be empty
    @Test(expected=IllegalArgumentException.class)
    public void translateKeyEmptySalt() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, EMPTY_BYTES, ITER);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.IllegalArgumentException: invalid iterationCount value
    @Test(expected=IllegalArgumentException.class)
    public void translateKeyZeroIterCount() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, 0);
        SecretKey pbeKey = skf.translateKey(key);
    }

    // java.lang.IllegalArgumentException: invalid iterationCount value
    @Test(expected=IllegalArgumentException.class)
    public void translateKeyNegativeIterCount() throws Exception {
        PBEKey key = KeyUtil.getDummyPBEKey(ALGORITHM, DK, FORMAT, PASSWORD, SALT, -1);
        SecretKey pbeKey = skf.translateKey(key);
    }

    private static void checkPBEKey(PBEKey key) {
        checkPBEKey(key, DK);
    }

    private static void checkPBEKey(PBEKey key, byte[] dk) {
        checkPBEKey(key, dk, PASSWORD);
    }

    private static void checkPBEKey(PBEKey key, byte[] dk, char[] pw) {
        checkPBEKey(key, dk, pw, ALGORITHM);
    }

    private static void checkPBEKey(PBEKey key, byte[] dk, char[] pw, String alg) {
        assertEquals(alg, key.getAlgorithm());
        assertArrayEquals(dk, key.getEncoded());
        assertEquals(FORMAT, key.getFormat());
        assertArrayEquals(pw, key.getPassword());
        assertArrayEquals(SALT, key.getSalt());
        assertEquals(ITER, key.getIterationCount());
    }

    private static void checkPBEKeySpec(PBEKeySpec ks) {
        checkPBEKeySpec(ks, PASSWORD);
    }

    private static void checkPBEKeySpec(PBEKeySpec ks, char[] pw) {
        assertEquals(DK.length * 8, ks.getKeyLength());
        assertArrayEquals(pw, ks.getPassword());
        assertArrayEquals(SALT, ks.getSalt());
        assertEquals(ITER, ks.getIterationCount());
    }

    private static int getUtf8Len(char[] charArray) {
        return new String(charArray).getBytes(StandardCharsets.UTF_8).length;
    }

    private static int get8BitLen(char[] charArray) {
        return new String(charArray).getBytes(StandardCharsets.US_ASCII).length;
    }
}
