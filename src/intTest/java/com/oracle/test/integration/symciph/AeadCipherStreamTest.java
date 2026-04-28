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

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.CipherInputStream;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

public class AeadCipherStreamTest {
    static final byte[] PLAIN_TEXT = "Plain Text".getBytes();

    static final String TRANSFORMATION = "AES/GCM/NoPadding";
    static final SecretKeySpec SECRET_KEY_SPEC = new SecretKeySpec(new byte[32], "AES");
    static final int TAG_LENGTH = 128;
    static final byte[] IV = TestUtil.hexToBytes("EE2004C053BF8E77C37899DC");
    static final AlgorithmParameterSpec ALG_PARAM_SPEC = new GCMParameterSpec(TAG_LENGTH, IV);

    static final byte[] CIPHER_TEXT = TestUtil.hexToBytes("D96567B89434D87EAC4677F38345C8052D976096E6F700292C62");

    private CipherInputStream createCipherInputStream(byte[] cipherText) throws Exception {
        InputStream inputStream = new ByteArrayInputStream(cipherText);
        Cipher cipher = ProviderUtil.getCipher(TRANSFORMATION);
        cipher.init(Cipher.DECRYPT_MODE, SECRET_KEY_SPEC, ALG_PARAM_SPEC);
        return new CipherInputStream(inputStream, cipher);
    }

    @Test
    public void cipherInputStreamTest() throws Exception {

        byte[] cipherText = Arrays.copyOf(CIPHER_TEXT, CIPHER_TEXT.length);
        byte[] decryptedText = new byte[PLAIN_TEXT.length];

        try (CipherInputStream cipherInputStream = createCipherInputStream(cipherText)) {
            // Read the expected number of plain text bytes from the cipher input stream
            cipherInputStream.read(decryptedText);
        }

        Assert.assertArrayEquals(PLAIN_TEXT, decryptedText);
    }

    @Test
    public void tamperedCipherInputStreamTest() throws Exception {
        byte[] cipherText = Arrays.copyOf(CIPHER_TEXT, CIPHER_TEXT.length);
        byte[] decryptedText = new byte[PLAIN_TEXT.length];

        // Tamper with the cipher text
        cipherText[cipherText.length/2] ^= 0x55;

        try (CipherInputStream cipherInputStream = createCipherInputStream(cipherText)) {
            // Read the expected number of plain text bytes from the cipher input stream.
            //   If 'jipher.cipher.AEAD.stream' is 'false' then
            //     no decrypted text will be returned until doFinal() is called. When doFinal() is called the AEAD tag
            //     check will fail and the javax.crypto.AEADBadTagException will be mapped to an java.io.IOException
            cipherInputStream.read(decryptedText);

            // When the stream is auto-closed:
            //   If 'jipher.cipher.AEAD.stream' is 'true' then
            //     this will result in doFinal() begin called. The AEAD tag check will fail and the
            //     java.security.ProviderException will propagate all the way to the application
        }  catch (IOException | ProviderException e) {
            // Expected exception, Ignore
            return;
        }
        Assert.fail("Should have thrown an exception when AEAD tag check failed");
    }
}
