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
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

public class AesKeyFactoryTest {

    SecretKeyFactory skf;

    @Before
    public void setUp() throws Exception {
        skf = ProviderUtil.getSecretKeyFactory("AES");
    }

    @Test
    public void generateSecret128() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff");
        SecretKey key = skf.generateSecret(new SecretKeySpec(testKey, "AES"));
        checkKey(key, testKey);
    }
    @Test
    public void generateSecret192() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff0011223344556677");
        SecretKey key = skf.generateSecret(new SecretKeySpec(testKey, "AES"));
        checkKey(key, testKey);
    }
    @Test
    public void generateSecret256() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        SecretKey key = skf.generateSecret(new SecretKeySpec(testKey, "AES"));
        checkKey(key, testKey);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateSecretInvalidLength() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddee");
        SecretKey key = skf.generateSecret(new SecretKeySpec(testKey, "AES"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateSecretInvalidSpec() throws Exception {
        SecretKey key = skf.generateSecret(new DESedeKeySpec(hexStringToByteArray("00112233445566778899aabbccddeeff0011223344556677")));
    }


    void checkKey(SecretKey key, byte[] bytes) {
        assertArrayEquals(bytes, key.getEncoded());
        assertEquals("AES", key.getAlgorithm());
        assertEquals("RAW", key.getFormat());
    }

    @Test
    public void getKeySpec() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff");
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("AES", testKey, "RAW"), SecretKeySpec.class);
        assertTrue(spec instanceof SecretKeySpec);
        checkKey((SecretKeySpec) spec, testKey);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecBadSpec() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddee");
        KeySpec spec = skf.getKeySpec(KeyUtil.getDummySecretKey("AES", testKey, "RAW"), DESedeKeySpec.class);
    }

    @Test
    public void translateKey128() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff");
        SecretKey skey = skf.translateKey(KeyUtil.getDummySecretKey("AES", testKey, "RAW"));
        checkKey(skey, testKey);
    }

    @Test
    public void translateKey192() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff0011223344556677");
        SecretKey skey = skf.translateKey(new SecretKeySpec(testKey, "RAW"));
        checkKey(skey, testKey);
    }

    @Test
    public void translateKey256() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899aabbccddeeff00112233445566778899aabbccddeeff");
        SecretKey skey = skf.translateKey(KeyUtil.getDummySecretKey("AES", testKey, "RAW"));
        checkKey(skey, testKey);
    }

    @Test(expected = InvalidKeyException.class)
    public void translateKeyInvalidLength() throws Exception {
        byte[] testKey = hexStringToByteArray("00112233445566778899");
        SecretKey skey = skf.translateKey(KeyUtil.getDummySecretKey("AES", testKey, "RAW"));
    }
}
