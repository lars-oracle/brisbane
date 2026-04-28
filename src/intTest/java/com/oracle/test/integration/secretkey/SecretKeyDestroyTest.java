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

package com.oracle.test.integration.secretkey;

import java.io.ByteArrayOutputStream;
import java.io.ObjectOutputStream;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class SecretKeyDestroyTest {

    static final char[] PASSWORD = "password".toCharArray();
    static final byte[] SALT = hexStringToByteArray("00112233445566778899AABBCCDDEEFF");
    static final int ITER = 1000;
    static final int KEY_LENGTH = 256;
    static final PBEKeySpec PBE_SPEC = new PBEKeySpec(PASSWORD, SALT, ITER, KEY_LENGTH);

    String keyType;
    SecretKey destroyedSecretKey;

    @Parameterized.Parameters(name="{0}")
    public static Collection<String> keyTypes() throws Exception {
        return Arrays.asList("PBE", "PBKDF");
    }

    public SecretKeyDestroyTest(String keyType) {
        this.keyType = keyType;
    }

    @Before
    public void createDestroyedSecretKey() throws Exception {
        SecretKeyFactory skf = switch (keyType) {
            case "PBE" -> ProviderUtil.getSecretKeyFactory("PBEWithHmacSHA256AndAES_256");
            case "PBKDF" -> ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA1");
            default -> throw new RuntimeException("Unsupported key type: " + keyType);
        };
        SecretKey secretKey = skf.generateSecret(PBE_SPEC);
        secretKey.destroy();

        destroyedSecretKey = secretKey;
    }

    @Test
    public void destroyKeyTest() {
        assertTrue(destroyedSecretKey.isDestroyed());
    }

    @Test(expected = IllegalStateException.class)
    public void getEncodingOfDestroyedKeyTest() {
        destroyedSecretKey.getEncoded();
    }

    @Test(expected = IllegalStateException.class)
    public void useDestroyedKeyTest() throws Exception {
        Cipher cipher = switch (keyType) {
            case "PBE" -> ProviderUtil.getCipher("PBEWithHmacSHA256AndAES_256");
            case "PBKDF" -> ProviderUtil.getCipher("AES");
            default -> throw new RuntimeException("Unsupported key type: " + keyType);
        };
        cipher.init(Cipher.ENCRYPT_MODE, destroyedSecretKey);
    }

    @Test(expected = IllegalStateException.class)
    public void translateDestroyedKeyTest() throws Exception {
        SecretKeyFactory secretKeyFactory = switch (keyType) {
            case "PBE" -> ProviderUtil.getSecretKeyFactory("PBEWithHmacSHA256AndAES_256");
            case "PBKDF" -> ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA1");
            default -> throw new RuntimeException("Unsupported key type: " + keyType);
        };
        secretKeyFactory.translateKey(destroyedSecretKey);
    }

    @Test(expected = IllegalStateException.class)
    public void serializeDestroyedKeyTest() throws Exception {
        ByteArrayOutputStream byteArrayOutputStream = new ByteArrayOutputStream();
        ObjectOutputStream objectOutputStream = new ObjectOutputStream(byteArrayOutputStream);
        objectOutputStream.writeObject(destroyedSecretKey);
    }
}
