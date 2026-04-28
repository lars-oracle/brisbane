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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeTrue;

public class AsymCipherTest {
    private static final String ALG = "RSA/ECB/OAEPPadding";

    PrivateKey privKey;
    PublicKey pubKey;
    AsymCipherTestVector tv;

    @Before
    public void setUp() throws Exception {
        tv = TestData.getFirst(AsymCipherTestVector.class, DataMatchers.alg(ALG));
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId()));
        privKey = KeyUtil.loadPrivate("RSA", kp.getPriv());
        pubKey = KeyUtil.loadPublic("RSA", kp.getPub());
    }

    Cipher getInitCipher(int mode) throws Exception {
        Cipher c = ProviderUtil.getCipher(ALG);
        c.init(mode, mode == Cipher.ENCRYPT_MODE || mode == Cipher.WRAP_MODE ? pubKey : privKey);
        return c;
    }

    void decrypt(byte[] ciphertext, byte[] expectedDecrypted) throws Exception {
        Cipher decrypter = ProviderUtil.getCipher(ALG);
        decrypter.init(Cipher.DECRYPT_MODE, privKey);
        decrypter.update(ciphertext);
        byte[] decrypted = decrypter.doFinal();
        assertArrayEquals(expectedDecrypted, decrypted);
    }

    /**
     * Test encrypt with byte[] update(byte[]), byte[] doFinal()
     *  - input in one update
     *  - input in multiple updates including empty array
     */
    @Test
    public void encryptUpdateDoFinalRet() throws Exception {
        doTestUpdateDoFinalRet(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Test decrypt with byte[] update(byte[]), byte[] doFinal()
     *  - input in one update
     *  - input in multiple updates including empty array
     */
    @Test
    public void decryptUpdateDoFinalRet() throws Exception {
        doTestUpdateDoFinalRet(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    private void doTestUpdateDoFinalRet(int cipherMode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(cipherMode);
        cipher.update(input);
        byte[] out = cipher.doFinal();
        if (cipherMode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    /**
     * Test encrypt with byte[] update(byte[], offset, len)
     */
    @Test
    public void encryptUpdateOffsetRet() throws Exception {
        doTestUpdateOffsetRet(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Test Decrypt with byte[] update(byte[], offset, len)
     */
    @Test
    public void decryptUpdateOffsetRet() throws Exception {
        doTestUpdateOffsetRet(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    private void doTestUpdateOffsetRet(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] out = cipher.update(input, 0, 0);
        assertNull(out);
        out = cipher.update(input, 0, 5);
        assertNull(out);
        out = cipher.update(input, 5, input.length - 5);
        assertNull(out);
        out = cipher.doFinal();
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    /**
     * Test encrypt with int update(byte[], int, int, byte[], int)
     */
    @Test
    public void encryptUpdateOut() throws Exception {
        updateOut(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Test decrypt with int update(byte[], int, int, byte[], int)
     */
    @Test
    public void decryptUpdateOut() throws Exception {
        updateOut(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void updateOut(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = 0;
        len += cipher.update(input, 0, 0, out, len);
        for (int i = 0; i < input.length; i++) {
            len += cipher.update(input, i, 1, out, len);
        }
        len += cipher.update(input, input.length, 0, out, len);
        len += cipher.doFinal(out, len);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
        } else {
            decrypt(Arrays.copyOf(out, len), input);
        }

        cipher = getInitCipher(mode);
        out = new byte[cipher.getOutputSize(input.length) + 11];
        int outOffset = 11;
        len = cipher.update(input, 0, 0, out, outOffset);
        for (int i = 0; i < input.length; i++) {
            len += cipher.update(input, i, 1, out, outOffset + len);
        }
        len += cipher.update(input, input.length, 0, out, outOffset + len);
        len += cipher.doFinal(out, outOffset + len);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(out, outOffset, outOffset + len));
        } else {
            decrypt(Arrays.copyOfRange(out, outOffset, outOffset + len), input);
        }
    }

    /**
     * Test encrypt with: void update(ByteBuffer, ByteBuffer)
     */
    @Test
    public void encryptUpdateByteBuffer() throws Exception {
        updateByteBuffer(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Test decrypt with: void update(ByteBuffer, ByteBuffer)
     */
    @Test
    public void decryptUpdateByteBuffer() throws Exception {
        updateByteBuffer(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void updateByteBuffer(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        ByteBuffer outbb = ByteBuffer.allocate(cipher.getOutputSize(input.length) *2);
        cipher.update(ByteBuffer.wrap(input), outbb);
        cipher.doFinal(ByteBuffer.wrap(new byte[0]),  outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        byte[] out = new byte[outbb.remaining()];
        outbb.get(out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }

        // input is direct byte buffer.
        cipher = getInitCipher(mode);
        outbb = ByteBuffer.allocate(cipher.getOutputSize(input.length) *2);
        cipher.update(TestUtil.directByteBuffer(input), outbb);
        cipher.doFinal(ByteBuffer.wrap(new byte[0]),  outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        out = new byte[outbb.remaining()];
        outbb.get(out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    /**
     * Testing encrypt with: byte[] doFinal(byte[])
     */
    @Test
    public void encryptDoFinalInputRet() throws Exception {
        doFinalInputRet(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Testing decrypt with: byte[] doFinal(byte[])
     */
    @Test
    public void decryptDoFinalInputRet() throws Exception {
        doFinalInputRet(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalInputRet(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] out = cipher.doFinal(input);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    /**
     * Testing encrypt with: byte[] doFinal(byte[], int, int)
     */
    @Test
    public void encryptDoFinalInputOffsetRet() throws Exception {
        doFinalInputOffsetRet(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Testing decrypt with: byte[] doFinal(byte[], int, int)
     */
    @Test
    public void decryptDoFinalInputOffsetRet() throws Exception {
        doFinalInputOffsetRet(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalInputOffsetRet(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        cipher.update(input, 0, 3);
        byte[] out = cipher.doFinal(input, 3, input.length -3);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    /**
     * Testing encrypt with: int doFinal(byte[], int, int, byte[])
     */
    @Test
    public void encryptDoFinalInputOffsetOutput() throws Exception {
        doFinalInputOffsetOutput(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Testing decrypt with: int doFinal(byte[], int, int, byte[])
     */
    @Test
    public void decryptDoFinalInputOffsetOutput() throws Exception {
        doFinalInputOffsetOutput(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalInputOffsetOutput(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.doFinal(input, 0, input.length, out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
        } else {
            decrypt(Arrays.copyOf(out, len), input);
        }

        cipher = getInitCipher(mode);
        byte[] inputOff = new byte[input.length + 11];
        System.arraycopy(input, 0, inputOff, 11, input.length);
        len = cipher.doFinal(inputOff, 11, input.length, out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
        } else {
            decrypt(Arrays.copyOf(out, len), input);
        }
    }

    /**
     * Testing encrypt with: int doFinal(byte[], int, int, byte[], int)
     */
    @Test
    public void encryptDoFinalInputOffsetOutputOffset() throws Exception {
        doFinalInputOffsetOutputOffset(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Testing decrypt with: int doFinal(byte[], int, int, byte[], int)
     */
    @Test
    public void decryptDoFinalInputOffsetOutputOffset() throws Exception {
        doFinalInputOffsetOutputOffset(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalInputOffsetOutputOffset(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] out = new byte[cipher.getOutputSize(input.length)];
        int len = cipher.doFinal(input, 0, input.length, out, 0);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
        } else {
            decrypt(Arrays.copyOf(out, len), input);
        }

        // Write to output buffer from a non-zero offset
        cipher = getInitCipher(mode);
        out = new byte[cipher.getOutputSize(input.length) +10];
        len = cipher.doFinal(input, 0, input.length, out, 10);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOfRange(out, 10, 10+len));
        } else {
            decrypt(Arrays.copyOfRange(out, 10, 10+len), input);
        }

        // Specify zero bytes of input
        cipher = getInitCipher(mode);
        len = cipher.update(input, 0, input.length, out);
        len += cipher.doFinal(input, 0, 0, out, len);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
        } else {
            decrypt(Arrays.copyOf(out, len), input);
        }
    }

    /**
     * Testing encrypt with: void doFinal(ByteBuffer, ByteBuffer)
     */
    @Test
    public void encryptDoFinalByteBuffer() throws Exception {
        doFinalByteBuffer(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    /**
     * Testing decrypt with: void doFinal(ByteBuffer, ByteBuffer)
     */
    @Test
    public void decryptDoFinalByteBuffer() throws Exception {
        doFinalByteBuffer(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalByteBuffer(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        ByteBuffer outbb = ByteBuffer.allocate(cipher.getOutputSize(expectedOutput.length) * 2);
        cipher.doFinal(ByteBuffer.wrap(input), outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        byte[] out = new byte[outbb.remaining()];
        outbb.get(out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }

        cipher = getInitCipher(mode);
        outbb = TestUtil.directByteBuffer(new byte[cipher.getOutputSize(expectedOutput.length) *2]);
        cipher.doFinal(TestUtil.directByteBuffer(input), outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        out = new byte[outbb.remaining()];
        outbb.get(out);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, out);
        } else {
            decrypt(out, input);
        }
    }

    @Test
    public void reuseCipherDoFinal() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        c.doFinal(tv.getData(), 0, tv.getData().length);

        byte[] otherPtext = TestUtil.randomBytes(tv.getData().length);
        byte[] result2 = c.doFinal(otherPtext);

        c.init(Cipher.DECRYPT_MODE, privKey);
        byte[] decrypted = c.doFinal(result2);

        assertArrayEquals(otherPtext, decrypted);

        byte[] out1 = c.update(tv.getCiphertext());
        byte[] out2  = c.doFinal();
        assertArrayEquals(tv.getData(), TestUtil.concat(out1, out2));
    }

    @Test
    public void encryptSameInputOutputBuf() throws Exception {
        doTestSameInputOutputBuf(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decryptSameInputOutputBuf() throws Exception {
        doTestSameInputOutputBuf(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doTestSameInputOutputBuf(int mode, byte[] input, byte[] output) throws Exception {
        Cipher c = getInitCipher(mode);
        byte[] buffer = new byte[Math.max(input.length, output.length)];
        System.arraycopy(input, 0, buffer, 0, input.length);
        int len = c.update(buffer, 0, input.length, buffer, 0);
        len += c.doFinal(buffer, len);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(output, Arrays.copyOf(buffer, len));
        } else {
            decrypt(Arrays.copyOf(buffer, len), input);
        }
    }

    @Test
    public void encryptOverlapLeftShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext(), -1);
    }

    @Test
    public void encryptOverlapRightShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext(), 1);
    }

    @Test
    public void decryptOverlapLeftShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData(), -1);
    }

    @Test
    public void decryptOverlapRightShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData(), 1);
    }

    void doTestOverlappedInputOutputBuf(int mode, byte[] input, byte[] output, int offset) throws Exception {
        assumeTrue("Invalid test - no overlap", input.length > offset);
        Cipher c = getInitCipher(mode);
        byte[] buffer = new byte[Math.max(input.length, output.length) + Math.abs(offset)];
        System.arraycopy(input, 0, buffer, Math.max(0, -offset), input.length);
        int len = c.update(buffer, Math.max(0, -offset), input.length, buffer, Math.max(0, offset));
        len += c.doFinal(buffer, Math.max(0, offset) + len);
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(output, Arrays.copyOfRange(buffer, Math.max(0, offset), Math.max(0, offset) + len));
        } else {
            decrypt(Arrays.copyOfRange(buffer, Math.max(0, offset), Math.max(0, offset) + len), input);
        }
    }

    // Tests that once init has been called the cipher object
    // is independent of the key passed to init
    // (which may be destroyed by the application)
    @Test
    public void decryptInitDestroyKeyDoFinal() throws Exception {
        PrivateKey key = KeyUtil.duplicate(privKey);
        Cipher cipher = ProviderUtil.getCipher(ALG);
        cipher.init(Cipher.DECRYPT_MODE, key);
        key.destroy();
        byte[] out = cipher.doFinal(tv.getCiphertext());
        assertArrayEquals(tv.getData(), out);
    }

    // Tests that an implicit (re)init following a key destroy works
    @Test
    public void decryptInitDoFinalDestroyKeyDoFinal() throws Exception {
        PrivateKey key = KeyUtil.duplicate(privKey);
        Cipher cipher = ProviderUtil.getCipher(ALG);
        cipher.init(Cipher.DECRYPT_MODE, key);
        cipher.doFinal(tv.getCiphertext());

        key.destroy();
        byte[] out = cipher.doFinal(tv.getCiphertext());
        assertArrayEquals(tv.getData(), out);
    }

    @Test
    public void wrap() throws Exception {
        Cipher c = getInitCipher(Cipher.WRAP_MODE);
        byte[] out = c.wrap(new SecretKeySpec(tv.getData(), ""));
        decrypt(out, tv.getData());
    }

    @Test
    public void unwrap() throws Exception {
        Cipher c = getInitCipher(Cipher.UNWRAP_MODE);
        Key key = c.unwrap(tv.getCiphertext(), "AES", Cipher.SECRET_KEY);
        assertArrayEquals(tv.getData(), key.getEncoded());
    }

    @Test
    public void wrapUnwrapPublicKey() throws Exception {
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE);
        PublicKey key = KeyUtil.loadPublic("EC", kp.getPub());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
        assertEquals(key, unwrapped);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to PRIVATE_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "DSNAY", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (NoSuchAlgorithmException e) {
            // Expected.
        }
    }

    @Test
    public void wrapUnwrapPrivateKey() throws Exception {
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE);
        PrivateKey key = KeyUtil.loadPrivate("EC", kp.getPriv());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
        assertEquals(key, unwrapped);

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to PUBLIC_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE);
        try {
            cipher.unwrap(wrapped, "DSNAY", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (NoSuchAlgorithmException e) {
            // Expected.
        }
    }

    @Test(expected = InvalidKeyException.class)
    public void unwrapDecryptFailure() throws Exception {
        Cipher cipher = getInitCipher(Cipher.UNWRAP_MODE);
        cipher.unwrap(new byte[15], "AES", Cipher.SECRET_KEY);
    }

    @Test(expected = UnsupportedOperationException.class)
    public void updateAad() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        c.updateAAD(tv.getData());
    }

    public void doFinalShortBufferRetry(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] output = new byte[cipher.getOutputSize(input.length) - 1];
        int len;
        try {
            len = cipher.doFinal(input, 0, input.length, output, 0);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            output = Arrays.copyOf(output, cipher.getOutputSize(input.length));
            len = cipher.doFinal(input, 0, input.length, output, 0);
        }
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(output, len));
        } else {
            decrypt(output, input);
        }
    }

    public void updateDoFinalShortBufferRetry(int mode, byte[] input, byte[] expectedOutput) throws Exception {
        Cipher cipher = getInitCipher(mode);
        byte[] output = new byte[cipher.getOutputSize(input.length) - 1];
        int outputOffset = cipher.update(input, 0, input.length, output, 0);
        try {
            outputOffset += cipher.doFinal(output, outputOffset);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            output = Arrays.copyOf(output, cipher.getOutputSize(input.length));
            outputOffset += cipher.doFinal(output, outputOffset);
        }
        if (mode == Cipher.DECRYPT_MODE) {
            assertArrayEquals(expectedOutput, Arrays.copyOf(output, outputOffset));
        } else {
            decrypt(output, input);
        }
    }

    @Test
    public void encryptDoFinalShortBufferRetry() throws Exception {
        doFinalShortBufferRetry(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptUpdateDoFinalShortBufferRetry() throws Exception {
        updateDoFinalShortBufferRetry(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decryptDoFinalShortBufferRetry() throws Exception {
        doFinalShortBufferRetry(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    @Test
    public void decryptUpdateDoFinalShortBufferRetry() throws Exception {
        updateDoFinalShortBufferRetry(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void negTestEncryptFinalDataTooLong() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        c.doFinal(new byte[257]);
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void negTestDecryptFinalDataTooLong() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
        c.doFinal(new byte[257]);
    }

    @Test(expected = IllegalBlockSizeException.class)
    public void negTestDecryptUpdateDataTooLong() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
        c.update(new byte[500]);
        c.doFinal();
    }
}
