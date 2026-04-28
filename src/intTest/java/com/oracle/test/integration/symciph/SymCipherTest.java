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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.AEADBadTagException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Ignore;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataSize;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.SymCipherTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.testdata.WrapCipherTestVector;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.jiphertest.testdata.DataMatchers.symMatcher;
import static com.oracle.jiphertest.testdata.DataSize.BASIC;
import static com.oracle.jiphertest.util.TestUtil.concat;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertTrue;
import static org.junit.Assert.fail;
import static org.junit.Assume.assumeFalse;
import static org.junit.Assume.assumeTrue;

/**
 * Tests for different API calls to get an encryption/decryption using standard symmetric cipher.
 * <p>
 * Different combinations of updateAAD,update,doFinal methods are tested.
 * Edge cases and negative cases are also included.
 */
public abstract class SymCipherTest {
    static boolean CIPHER_AEAD_STREAM_VALUE = Boolean.getBoolean("jipher.cipher.AEAD.stream");
    static String EXPECTED_AEAD_BAD_TAG_EXCEPTION = CIPHER_AEAD_STREAM_VALUE ?
            "java.security.ProviderException" : "javax.crypto.AEADBadTagException";

    SymCipherTestVector tv;
    String keyAlg;
    AlgorithmParameterSpec initSpec;

    SymCipherTest(SymCipherTestVector tv) {
        this.tv = tv;
        this.keyAlg = tv.getAlg().split("/")[0];
        this.initSpec = createSpec(tv);
    }

    Cipher getInitCipher(int mode, boolean aad) throws Exception {
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        c.init(mode, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), initSpec);
        if (aad && tv.getAad() != null) {
            c.updateAAD(tv.getAad());
        }
        return c;
    }

    Cipher getInitCipher(int mode) throws Exception {
        return getInitCipher(mode, true);
    }

    /**
     * Create an appropriate AlgorithmParameterSpec for use within init of the cipher
     * for the test vector.
     * @param tv the test vector
     * @return the algorithm param spec
     */
    abstract AlgorithmParameterSpec createSpec(SymCipherTestVector tv);

    /**
     * Create an AlgorithmParameterSpec that does not represent the test vector parameters.
     * @param tv the test vector
     * @return the algorithm param spec
     */
    abstract AlgorithmParameterSpec createModifiedSpec(SymCipherTestVector tv);

    public static abstract class PaddedCipherTest extends SymCipherTest {

        public PaddedCipherTest(SymCipherTestVector tv) {
            super(tv);
        }

        @Override
        AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
            return new IvParameterSpec(tv.getCiphParams().getIv());
        }

        @Override
        AlgorithmParameterSpec createModifiedSpec(SymCipherTestVector tv) {
            // Create IV spec with all zeros.
            return new IvParameterSpec(new byte[tv.getCiphParams().getIv().length]);
        }

        @Test(expected = IllegalStateException.class)
        public void negTestUpdateAADNotSupported() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            c.updateAAD(new byte[10]);
        }

        @Test(expected = IllegalStateException.class)
        public void negTestUpdateAADByteBufferNotSupported() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            c.updateAAD(ByteBuffer.wrap(new byte[10]));
        }

        @Test
        public void encryptDecryptAutoGenIv() throws Exception {
            Cipher c = ProviderUtil.getCipher("AES/CBC/PKCS5Padding");

            SecretKeySpec keySpec = new SecretKeySpec(tv.getKey(), "AES");
            c.init(Cipher.ENCRYPT_MODE, keySpec, (SecureRandom) null);
            byte[] data = "abcdefg".getBytes();
            byte[] ctext = c.doFinal(data, 0, data.length);

            byte[] iv = c.getIV();
            if (Arrays.equals(new byte[16], iv)) {
                fail("IV was all zeros");
            }
            assertEquals(16, iv.length);

            c = ProviderUtil.getCipher("AES/CBC/PKCS5Padding");
            c.init(Cipher.DECRYPT_MODE, keySpec, new IvParameterSpec(iv));
            byte[] decrypted = c.doFinal(ctext, 0, ctext.length);
            assertArrayEquals(data, decrypted);
        }

        @Test
        public void autoGenIvEachInit() throws Exception {
            Cipher c = ProviderUtil.getCipher("AES/CBC/PKCS5Padding");
            SecretKeySpec keySpec = new SecretKeySpec(tv.getKey(), "AES");
            c.init(Cipher.ENCRYPT_MODE, keySpec, (SecureRandom) null);
            byte[] iv = c.getIV();

            c.init(Cipher.ENCRYPT_MODE, keySpec, (SecureRandom) null);
            byte[] iv2 = c.getIV();
            assertFalse("Successive auto-gen IVs were the same", Arrays.equals(iv, iv2));
        }
    }

    public static class PaddedCipherBlockAlignedTest extends PaddedCipherTest {
        public PaddedCipherBlockAlignedTest() throws Exception {
            super(TestData.getFirst(SymCipherTestVector.class, symMatcher().alg("AES/CBC/PKCS5Padding").dataMin(49).blockAligned(16)));
        }

        @Test
        public void encryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            // The update() call is not expected to throw ShortBufferException because final (full) padding block
            // will be output by doFinal()
            updateDoFinalShortBufferRetry(c, tv.getData(), tv.getCiphertext(), false);
        }

        @Test
        public void decryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
            // The update() call is expected to throw ShortBufferException because update() should process all but the
            // final (full) padding block and the resulting output should not fit in plaintext length - 1 bytes.
            updateDoFinalShortBufferRetry(c, tv.getCiphertext(), tv.getData(), true);
        }
    }

    public static class PaddedCipherBlockUnalignedTest extends PaddedCipherTest {
        public PaddedCipherBlockUnalignedTest() throws Exception {
            super(TestData.getFirst(SymCipherTestVector.class, symMatcher().alg("AES/CBC/PKCS5Padding").dataMin(49).blockUnaligned(16)));
        }

        @Test
        public void encryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            // The update() call not is expected to throw ShortBufferException because it should not process the final partial block.
            updateDoFinalShortBufferRetry(c, tv.getData(), tv.getCiphertext(), false);
        }

        @Test
        public void decryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
            // The update() call not is expected to throw ShortBufferException because it should not process the final partial block.
            updateDoFinalShortBufferRetry(c, tv.getCiphertext(), tv.getData(), false);
        }
    }

    public static class AeadCipherTest extends SymCipherTest {

        private final byte[] authTag;

        public AeadCipherTest() throws Exception {
            super(TestData.getFirst(SymCipherTestVector.class,
                    symMatcher().alg("AES/GCM/NoPadding").dataMin(49).aad(BASIC)));
            this.authTag = tv.getAuthTag();
        }

        @Test
        public void decryptUpdateOffsetRet() throws Exception {
            super.decryptUpdateOffsetRet();
        }

        @Test
        public void decryptUpdateOut() throws Exception {
            super.decryptUpdateOut();
        }

        @Override
        AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
            return new GCMParameterSpec(tv.getCiphParams().getTagLen(), tv.getCiphParams().getIv());
        }

        @Override
        AlgorithmParameterSpec createModifiedSpec(SymCipherTestVector tv) {
            return new GCMParameterSpec(((GCMParameterSpec) this.initSpec).getTLen(), new byte[((GCMParameterSpec) this.initSpec).getIV().length]);
        }

        @Test
        public void testUpdateAADByteBuffer() throws Exception {
            Cipher c = ProviderUtil.getCipher(tv.getAlg());
            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), initSpec);
            c.updateAAD(ByteBuffer.wrap(tv.getAad()));
            byte[] out = c.doFinal(tv.getData(), 0, tv.getData().length);
            Assert.assertArrayEquals(this.tv.getCiphertext(), out);

            c.init(Cipher.ENCRYPT_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), initSpec);
            c.updateAAD(TestUtil.directByteBuffer(tv.getAad()));
            out = c.doFinal(tv.getData(), 0, tv.getData().length);
            Assert.assertArrayEquals(this.tv.getCiphertext(), out);
        }

        @Test
        public void testUpdateAADParts() throws Exception {
            Cipher c = ProviderUtil.getCipher(tv.getAlg());
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), initSpec);
            for (int i = 0; i < this.tv.getAad().length; i++) {
                c.updateAAD(this.tv.getAad(), i, 1);
            }
            c.updateAAD(this.tv.getAad(), 0, 0);
            byte[] out = c.doFinal(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length);
            Assert.assertArrayEquals(tv.getData(), out);
        }

        @Test(expected = IllegalStateException.class)
        public void negTestUpdateAADAfterUpdate() throws Exception {
            Cipher c = ProviderUtil.getCipher(tv.getAlg());
            c.init(Cipher.DECRYPT_MODE, new SecretKeySpec(tv.getKey(), 0, tv.getKey().length, keyAlg), initSpec);
            c.updateAAD(this.tv.getAad(), 0, this.tv.getAad().length);
            c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length);
            c.updateAAD(this.tv.getAad());
        }

        @Test
        public void negTestDecFailureTagChanged() throws Exception {
            try {
                Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
                byte[] out = new byte[tv.getData().length];
                int len = c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length - this.authTag.length, out, 0);
                this.authTag[0]++;
                c.doFinal(this.authTag, 0, this.authTag.length, out, len);
                fail("Failed to throw " + EXPECTED_AEAD_BAD_TAG_EXCEPTION);
            } catch (AEADBadTagException e) {
                assertFalse("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<javax.crypto.AEADBadTagException>", CIPHER_AEAD_STREAM_VALUE);
            } catch (ProviderException e) {
                assertTrue("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<java.lang.ProviderException>", CIPHER_AEAD_STREAM_VALUE);
            }
        }

        @Test
        public void negTestDecFailureTagShort() throws Exception {
            try {
                Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
                byte[] out = new byte[tv.getData().length];
                int len = c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length - this.authTag.length, out, 0);
                c.doFinal(this.authTag, 0, this.authTag.length - 1, out, len);
                fail("Failed to throw " + EXPECTED_AEAD_BAD_TAG_EXCEPTION);
            } catch (AEADBadTagException e) {
                assertFalse("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<javax.crypto.AEADBadTagException>", CIPHER_AEAD_STREAM_VALUE);
            } catch (ProviderException e) {
                assertTrue("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<java.lang.ProviderException>", CIPHER_AEAD_STREAM_VALUE);
            }
        }

        @Test
        public void negTestDecFailureTagLong() throws Exception {
            try {
                Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
                byte[] out = new byte[this.tv.getCiphertext().length];
                int len = c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length, out, 0);
                c.doFinal(this.authTag, 0, 1, out, len);
                fail("Failed to throw " + EXPECTED_AEAD_BAD_TAG_EXCEPTION);
            } catch (AEADBadTagException e) {
                assertFalse("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<javax.crypto.AEADBadTagException>", CIPHER_AEAD_STREAM_VALUE);
            } catch (ProviderException e) {
                assertTrue("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<java.lang.ProviderException>", CIPHER_AEAD_STREAM_VALUE);
            }
        }

        @Test
        public void negTestDecFailureTagMissing() throws Exception {
            try {
                Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
                byte[] out = new byte[tv.getData().length];
                int len = c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length - this.authTag.length, out, 0);
                c.doFinal(out, len);
                fail("Failed to throw " + EXPECTED_AEAD_BAD_TAG_EXCEPTION);
            } catch (AEADBadTagException e) {
                assertFalse("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<javax.crypto.AEADBadTagException>", CIPHER_AEAD_STREAM_VALUE);
            } catch (ProviderException e) {
                assertTrue("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+" " +
                        "but was<java.lang.ProviderException>", CIPHER_AEAD_STREAM_VALUE);
            }
        }

        @Test
        public void negTestDecFailureCiphertextShort() throws Exception {
            try {
                Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
                byte[] out = new byte[tv.getData().length];
                int len = c.update(this.tv.getCiphertext(), 0, this.tv.getCiphertext().length - this.authTag.length - 1, out, 0);
                c.doFinal(out, len);
                fail("Failed to throw " + EXPECTED_AEAD_BAD_TAG_EXCEPTION);
            } catch (AEADBadTagException e) {
                assertFalse("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> "+
                        "but was<javax.crypto.AEADBadTagException>", CIPHER_AEAD_STREAM_VALUE);
            } catch (ProviderException e) {
                assertTrue("Unexpected exception, expected<"+EXPECTED_AEAD_BAD_TAG_EXCEPTION+"> " +
                        "but was<java.lang.ProviderException>", CIPHER_AEAD_STREAM_VALUE);
            }
        }

        @Test
        public void decryptUpdateShortBufferRetry() throws Exception {
            assumeTrue("Test assumes that jipher.cipher.AEAD.stream System property is true", CIPHER_AEAD_STREAM_VALUE);
            super.decryptUpdateShortBufferRetry();
        }

        @Test
        public void decryptUpdateUpdateShortBufferRetry() throws Exception {
            assumeTrue("Test assumes that jipher.cipher.AEAD.stream System property is true", CIPHER_AEAD_STREAM_VALUE);
            super.decryptUpdateUpdateShortBufferRetry();
        }

        @Test
        public void encryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            // The update() call is not expected to throw ShortBufferException because the tag is not appended until doFinal()
            updateDoFinalShortBufferRetry(c, tv.getData(), tv.getCiphertext(),false);
        }

        @Test
        public void decryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
            // The update() call is expected to throw ShortBufferException when jipher.cipher.AEAD.stream is set
            // to true because it should process all BUT the last tag length bytes of the input and this should
            // not fit in the plaintext length - 1 bytes provided.
            updateDoFinalShortBufferRetry(c, tv.getCiphertext(), tv.getData(), CIPHER_AEAD_STREAM_VALUE);
        }
    }

    public static class NoPadBlockCipherTest extends SymCipherTest {
        public NoPadBlockCipherTest() throws Exception {
            super(TestData.getFirst(SymCipherTestVector.class,
                    symMatcher().alg("AES/CBC/NoPadding").dataMin(49)));
        }

        @Override
        AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
            return new IvParameterSpec(tv.getCiphParams().getIv());
        }

        @Override
        AlgorithmParameterSpec createModifiedSpec(SymCipherTestVector tv) {
            return new IvParameterSpec(new byte[tv.getCiphParams().getIv().length]);
        }

        @Test(expected = IllegalBlockSizeException.class)
        public void invalidBlockSizeEncrypt() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            c.doFinal(new byte[15], 0, 15);
        }

        @Test(expected = IllegalBlockSizeException.class)
        public void invalidBlockSizeDecrypt() throws Exception {
            Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
            c.doFinal(new byte[15], 0, 15);
        }

        @Override
        @Test
        @Ignore public void wrapUnwrapPublicKey() {
            // Override and disable this test since we need key whose length is multiple of blocksize
        }

        @Override
        @Test
        @Ignore public void wrapUnwrapPrivateKey() {
            // Override and disable this test since we need key whose length is multiple of blocksize
        }

        @Test
        public void encryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
            // The update() call is expected to throw ShortBufferException because it is expected to
            // process all the input which should not fit into the output length - 1
            updateDoFinalShortBufferRetry(c, tv.getData(), tv.getCiphertext(),true);
        }

        @Test
        public void decryptUpdateDoFinalShortBufferRetry() throws Exception {
            Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
            // The update() call is expected to throw ShortBufferException because it is expected to
            // process all the input which should not fit into the output length - 1
            updateDoFinalShortBufferRetry(c, tv.getCiphertext(), tv.getData(),true);
        }
    }

    public static class WrapCipherTest extends SymCipherTest {

        public WrapCipherTest() throws Exception {
            super(TestData.getFirst(WrapCipherTestVector.class, symMatcher().alg("AESWrap").dataMin(32).blockAligned(16)));
        }

        @Override
        AlgorithmParameterSpec createSpec(SymCipherTestVector tv) {
            return null;
        }

        @Override
        AlgorithmParameterSpec createModifiedSpec(SymCipherTestVector tv) {
            return null;
        }

        @Override
        @Test
        @Ignore
        public void wrapUnwrapPublicKey() {
            // Override and disable this test since we need key whose length is multiple of blocksize
        }

        @Override
        @Test
        @Ignore
        public void wrapUnwrapPrivateKey() {
            // Override and disable this test since we need key whose length is multiple of blocksize
        }
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
        byte[] out1 = cipher.update(input);
        byte[] out2 = cipher.doFinal();
        assertArrayEquals(expectedOutput, concat(out1, out2));

        cipher = getInitCipher(cipherMode);
        byte[] in1 = Arrays.copyOf(input, 7);
        byte[] in2 = Arrays.copyOfRange(input, 7, input.length);
        out1 = cipher.update(in1);
        out2 = cipher.update(in2);
        byte[] out3 = cipher.update(new byte[0]);
        byte[] out4 = cipher.doFinal();
        assertArrayEquals(expectedOutput, concat(out1, out2, out3, out4));
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
        byte[] out1 = cipher.update(input, 0, 0);
        byte[] out2 = cipher.update(input, 0, 5);
        byte[] out3 = cipher.update(input, 5, 17);
        byte[] out4 = cipher.update(input, 22, input.length - 17 - 5);
        byte[] out5 = cipher.doFinal();
        assertArrayEquals(expectedOutput, concat(out1, out2, out3, out4, out5));
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
        byte[] out = new byte[expectedOutput.length];
        int len = 0;
        len += cipher.update(input, 0, 0, out, len);
        for (int i = 0; i < input.length; i++) {
            len += cipher.update(input, i, 1, out, len);
        }
        len += cipher.update(input, input.length, 0, out, len);
        len += cipher.doFinal(out, len);
        assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));

        cipher = getInitCipher(mode);
        out = new byte[expectedOutput.length + 11];
        int outOffset = 11;
        len = cipher.update(input, 0, 0, out, outOffset);
        for (int i = 0; i < input.length; i++) {
            len += cipher.update(input, i, 1, out, outOffset + len);
        }
        len += cipher.update(input, input.length, 0, out, outOffset + len);
        len += cipher.doFinal(out, outOffset + len);
        assertArrayEquals(expectedOutput, Arrays.copyOfRange(out, outOffset, outOffset+len));
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

        // When relying on the ByteBuffer support in javax.crypto.CipherSpi, we must ensure that the output
        // ByteBuffer has at least getOutputSize() bytes remaining. When overrides for the javax.crypto.CipherSpi
        // engine methods that take a ByteBuffer have been implemented it should be possible to have
        // the remaining bytes in the output ByteBuffer equal to expectedOutput.length for padded CBC decrypt.
        int outBufSize = mode == Cipher.DECRYPT_MODE ? cipher.getOutputSize(input.length) : expectedOutput.length;

        ByteBuffer outbb = ByteBuffer.allocate(outBufSize);
        cipher.update(ByteBuffer.wrap(input), outbb);
        cipher.doFinal(ByteBuffer.wrap(new byte[0]),  outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        byte[] out = new byte[outbb.remaining()];
        outbb.get(out);
        assertArrayEquals(expectedOutput, out);


        // input is direct byte buffer.
        cipher = getInitCipher(mode);
        outbb = ByteBuffer.allocate(outBufSize);
        cipher.update(TestUtil.directByteBuffer(input), outbb);
        cipher.doFinal(ByteBuffer.wrap(new byte[0]),  outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        out = new byte[outbb.remaining()];
        outbb.get(out);
        assertArrayEquals(expectedOutput, out);
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
        assertArrayEquals(expectedOutput, out);
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
        byte[] out1 = cipher.update(input, 0, 3);
        byte[] out2 = cipher.doFinal(input, 3, input.length -3);
        assertArrayEquals(expectedOutput, concat(out1, out2));
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
        byte[] out = new byte[expectedOutput.length];
        int len = cipher.doFinal(input, 0, input.length, out);
        assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));

        cipher = getInitCipher(mode);
        byte[] inputOff = new byte[input.length + 11];
        System.arraycopy(input, 0, inputOff, 11, input.length);
        len = cipher.doFinal(inputOff, 11, input.length, out);
        assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
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
        byte[] out = new byte[expectedOutput.length];
        int len = cipher.doFinal(input, 0, input.length, out, 0);
        assertArrayEquals(expectedOutput, Arrays.copyOfRange(out, 0, len));

        // Write to output buffer from a non-zero offset
        cipher = getInitCipher(mode);
        out = new byte[expectedOutput.length +10];
        len = cipher.doFinal(input, 0, input.length, out, 10);
        assertArrayEquals(expectedOutput, Arrays.copyOfRange(out, 10, len + 10));

        // Specify zero bytes of input
        cipher = getInitCipher(mode);
        len = cipher.update(input, 0, input.length, out);
        len += cipher.doFinal(input, 0, 0, out, len);
        assertArrayEquals(expectedOutput, Arrays.copyOf(out, len));
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

        // When relying on the ByteBuffer support in javax.crypto.CipherSpi, we must ensure that the output
        // ByteBuffer has at least getOutputSize() bytes remaining. When overrides for the javax.crypto.CipherSpi
        // engine methods that take a ByteBuffer have been implemented it should be possible to have
        // the remaining bytes in the output ByteBuffer equal to expectedOutput.length for padded CBC decrypt.
        int outBufSize = mode == Cipher.DECRYPT_MODE ? cipher.getOutputSize(input.length) : expectedOutput.length;

        ByteBuffer outbb = ByteBuffer.allocate(outBufSize);
        cipher.doFinal(ByteBuffer.wrap(input), outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        byte[] out = new byte[outbb.remaining()];
        outbb.get(out);
        assertArrayEquals(expectedOutput, out);

        cipher = getInitCipher(mode);
        outbb = TestUtil.directByteBuffer(new byte[outBufSize]);
        cipher.doFinal(TestUtil.directByteBuffer(input), outbb);
        outbb.limit(outbb.position());
        outbb.rewind();
        out = new byte[outbb.remaining()];
        outbb.get(out);
        assertArrayEquals(expectedOutput, out);
    }

    @Test
    public void reInit() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        c.update(tv.getData(), 0, tv.getData().length /2);

        SecretKey newKey = new SecretKeySpec(new byte[tv.getKey().length], this.keyAlg);
        AlgorithmParameterSpec spec = createModifiedSpec(tv);
        c.init(Cipher.ENCRYPT_MODE, newKey, spec);
        byte[] ctext = c.doFinal(tv.getData(), 0, tv.getData().length);
        assertFalse("Ciphertext from different parameters should be different", Arrays.equals(ctext, tv.getCiphertext()));

        Cipher d = ProviderUtil.getCipher(tv.getAlg());
        d.init(Cipher.DECRYPT_MODE, newKey, spec);
        byte[] decrypted = d.doFinal(ctext);
        assertArrayEquals(tv.getData(), decrypted);
    }

    @Test
    public void encryptUpdateSameInputOutputBuf() throws Exception {
        updateSameInputOutputBuf(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decryptUpdateSameInputOutputBuf() throws Exception {
        updateSameInputOutputBuf(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void updateSameInputOutputBuf(int mode, byte[] input, byte[] output) throws Exception {
        Cipher c = getInitCipher(mode);
        byte[] unprocessed = new byte[Math.max(input.length, output.length)];
        System.arraycopy(input, 0, unprocessed, 0, input.length);

        byte[] buffer = Arrays.copyOf(unprocessed, unprocessed.length);
        int len = c.update(buffer, 0, input.length, buffer, 0);

        assertArrayEquals("No unprocessed input data is overwritten when the result is copied into the output buffer",
                Arrays.copyOfRange(unprocessed, len, unprocessed.length), Arrays.copyOfRange(buffer, len, buffer.length));
        assertArrayEquals("Processed output should match expected output",
                Arrays.copyOf(output, len), Arrays.copyOf(buffer, len));
    }

    @Test
    public void encryptDoFinalSameInputOutputBuf() throws Exception {
        doFinalSameInputOutputBuf(Cipher.ENCRYPT_MODE, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decryptDoFinalSameInputOutputBuf() throws Exception {
        doFinalSameInputOutputBuf(Cipher.DECRYPT_MODE, tv.getCiphertext(), tv.getData());
    }

    void doFinalSameInputOutputBuf(int mode, byte[] input, byte[] output) throws Exception {
        Cipher c = getInitCipher(mode);
        byte[] unprocessed = new byte[Math.max(input.length, output.length)];
        System.arraycopy(input, 0, unprocessed, 0, input.length);

        byte[] buffer = Arrays.copyOf(unprocessed, unprocessed.length);
        int len = c.doFinal(buffer, 0, input.length, buffer, 0);

        assertArrayEquals("No unprocessed input data is overwritten when the result is copied into the output buffer",
                Arrays.copyOfRange(unprocessed, len, unprocessed.length), Arrays.copyOfRange(buffer, len, buffer.length));
        assertArrayEquals("Processed output should match expected output",
                Arrays.copyOf(output, len), Arrays.copyOf(buffer, len));
    }

    @Test
    public void encryptOverlapLeftShift512() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -512);
    }

    @Test
    public void encryptOverlapLeftShift33() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -33);
    }

    @Test
    public void encryptOverlapLeftShift32() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -32);
    }

    @Test
    public void encryptOverlapLeftShift17() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -17);
    }

    @Test
    public void encryptOverlapLeftShift16() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -16);
    }

    @Test
    public void encryptOverlapLeftShift9() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -9);
    }

    @Test
    public void encryptOverlapLeftShift8() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -8);
    }

    @Test
    public void encryptOverlapLeftShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, -1);
    }

    @Test
    public void encryptOverlapRightShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 1);
    }

    @Test
    public void encryptOverlapRightShift8() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 8);
    }

    @Test
    public void encryptOverlapRightShift9() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 9);
    }

    @Test
    public void encryptOverlapRightShift16() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 16);
    }

    @Test
    public void encryptOverlapRightShift17() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 17);
    }

    @Test
    public void encryptOverlapRightShift32() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 32);
    }

    @Test
    public void encryptOverlapRightShift33() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 33);
    }

    @Test
    public void encryptOverlapRightShift512() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.ENCRYPT_MODE, 512);
    }

    @Test
    public void decryptOverlapLeftShift512() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -512);
    }

    @Test
    public void decryptOverlapLeftShift33() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -33);
    }

    @Test
    public void decryptOverlapLeftShift32() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -32);
    }

    @Test
    public void decryptOverlapLeftShift17() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -17);
    }

    @Test
    public void decryptOverlapLeftShift16() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -16);
    }

    @Test
    public void decryptOverlapLeftShift9() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -9);
    }

    @Test
    public void decryptOverlapLeftShift8() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -8);
    }

    @Test
    public void decryptOverlapLeftShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, -1);
    }

    @Test
    public void decryptOverlapRightShift1() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 1);
    }

    @Test
    public void decryptOverlapRightShift8() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 8);
    }

    @Test
    public void decryptOverlapRightShift9() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 9);
    }

    @Test
    public void decryptOverlapRightShift16() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 16);
    }

    @Test
    public void decryptOverlapRightShift17() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 17);
    }

    @Test
    public void decryptOverlapRightShift32() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 32);
    }

    @Test
    public void decryptOverlapRightShift33() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 33);
    }

    @Test
    public void decryptOverlapRightShift512() throws Exception {
        doTestOverlappedInputOutputBuf(Cipher.DECRYPT_MODE, 512);
    }

    void doTestOverlappedInputOutputBuf(int mode, int offset) throws Exception {
        byte[] input, output;
        int length = Math.abs(offset) + 16; // Require at least 1 block overlap

        assumeTrue("Test only supports (en/de)crypt", (mode == Cipher.ENCRYPT_MODE) || (mode == Cipher.DECRYPT_MODE));
        if (mode == Cipher.ENCRYPT_MODE) {
            if (tv.getData().length < length) {
                // Generate a sufficiently large test vector
                input = new byte[length];
                Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
                output = c.doFinal(input);
            } else {
                input = tv.getData();
                output = tv.getCiphertext();
            }
        } else { // (mode == Cipher.DECRYPT_MODE)
            if (tv.getCiphertext().length < length) {
                assumeFalse("Test does not support generating Auth tag", tv.getAlg().contains("/") && tv.getAlg().split("/")[1].equalsIgnoreCase("GCM"));
                // Generate a sufficiently large test vector
                output = new byte[length];
                Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
                input = c.doFinal(output);
            } else {
                input = tv.getCiphertext();
                output = tv.getData();
            }
        }
        doTestOverlappedInputOutputBuf(mode, input, output, offset);
    }

    void doTestOverlappedInputOutputBuf(int mode, byte[] input, byte[] output, int offset) throws Exception {
        Cipher c = getInitCipher(mode);
        byte[] buffer = new byte[Math.max(input.length, output.length) + Math.abs(offset)];
        System.arraycopy(input, 0, buffer, Math.max(0, -offset), input.length);
        int len = c.update(buffer, Math.max(0, -offset), input.length, buffer, Math.max(0, offset));
        len += c.doFinal(buffer, Math.max(0, offset) + len);
        assertArrayEquals(output, Arrays.copyOfRange(buffer, Math.max(0, offset), Math.max(0, offset) + len));
    }

    void updateShortBufferRetry(Cipher c, byte[] input, byte[] expectedOutput) throws Exception {
        byte[] output = new byte[c.getBlockSize() - 1];
        try {
            int outputLen = c.update(input, 0, input.length, output, 0);
            Assume.assumeTrue("Some transformations such as Wrap/Unwrap only produce output on doFinal", outputLen != 0);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            output = new byte[expectedOutput.length];
            int outputOffset = c.update(input, 0, input.length, output, 0);
            c.doFinal(output, outputOffset);
        }
        assertArrayEquals(expectedOutput, output);
    }

    void updateUpdateShortBufferRetry(Cipher c, byte[] input, byte[] expectedOutput) throws Exception {

        // Prime the cipher engine with a partial block
        int inputOffset = 0;
        int outputOffset = 0;
        int inputLen = c.getBlockSize() - 1;
        byte[] output = new byte[inputLen];
        int outputLen = c.update(input, inputOffset, inputLen, output, outputOffset);

        inputOffset += inputLen;
        outputOffset += outputLen;
        inputLen = input.length - inputOffset;

        try {
            outputLen = c.update(input, inputOffset, inputLen, output, outputOffset);
            Assume.assumeTrue("Some transforms such as Wrap/Unrwrap only produce output on doFinal", outputLen != 0);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            output = Arrays.copyOf(output, expectedOutput.length);
            outputLen = c.update(input, inputOffset, inputLen, output, outputOffset);

            outputOffset += outputLen;
            c.doFinal(output, outputOffset);
        }
        assertArrayEquals(expectedOutput, output);
    }

    public void doFinalShortBufferRetry(Cipher c, byte[] input, byte[] expectedOutput) throws Exception {
        byte[] output = new byte[expectedOutput.length - 1];
        try {
            c.doFinal(input, 0, input.length, output, 0);
            fail("Failed to throw ShortBufferException");
        } catch (ShortBufferException e) {
            output = Arrays.copyOf(output, expectedOutput.length);
            int outputLen = c.doFinal(input, 0, input.length, output, 0);
            output = Arrays.copyOf(output, outputLen);
        }
        assertArrayEquals(expectedOutput, output);
    }

    public void updateDoFinalShortBufferRetry(Cipher c, byte[] input, byte[] expectedOutput, boolean expectUpdateToThrow) throws Exception {
        int outputOffset;
        byte[] output = new byte[expectedOutput.length - 1];
        try {
            outputOffset = c.update(input, 0, input.length, output, 0);
            assertFalse("Failed to throw ShortBufferException", expectUpdateToThrow);
            try {
                c.doFinal(output, outputOffset);
                fail("Failed to throw ShortBufferException");
            } catch (ShortBufferException e) {
                output = Arrays.copyOf(output, expectedOutput.length);
                c.doFinal(output, outputOffset);
            }
        } catch (ShortBufferException e) {
            assertTrue("Threw ShortBufferException unexpectedly", expectUpdateToThrow);
            output = new byte[expectedOutput.length];
            outputOffset = c.update(input, 0, input.length, output, 0);
            c.doFinal(output, outputOffset);
        }

        assertArrayEquals(expectedOutput, output);
    }

    @Test
    public void encryptUpdateShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        updateShortBufferRetry(c, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptUpdateUpdateShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        updateUpdateShortBufferRetry(c, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void encryptDoFinalShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.ENCRYPT_MODE);
        doFinalShortBufferRetry(c, tv.getData(), tv.getCiphertext());
    }

    @Test
    public void decryptUpdateShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
        updateShortBufferRetry(c, tv.getCiphertext(), tv.getData());
    }

    @Test
    public void decryptUpdateUpdateShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
        updateUpdateShortBufferRetry(c, tv.getCiphertext(), tv.getData());
    }

    @Test
    public void decryptDoFinalShortBufferRetry() throws Exception {
        Cipher c = getInitCipher(Cipher.DECRYPT_MODE);
        doFinalShortBufferRetry(c, tv.getCiphertext(), tv.getData());
    }

    @Test
    public void wrap() throws Exception {
        SymCipherTestVector wraptv = TestData.getFirst(tv.getClass(),
                symMatcher().alg(tv.getAlg()).dataSize(DataSize.BASIC).aad(DataSize.EMPTY));
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        c.init(Cipher.WRAP_MODE, new SecretKeySpec(wraptv.getKey(), 0, wraptv.getKey().length, keyAlg), createSpec(wraptv));
        byte[] out = c.wrap(new SecretKeySpec(wraptv.getData(), ""));
        assertArrayEquals(wraptv.getCiphertext(), out);
    }

    @Test
    public void unwrap() throws Exception {
        SymCipherTestVector wraptv = TestData.getFirst(tv.getClass(),
                symMatcher().alg(tv.getAlg()).dataSize(DataSize.BASIC).aad(DataSize.EMPTY));
        Cipher c = ProviderUtil.getCipher(tv.getAlg());
        c.init(Cipher.UNWRAP_MODE, new SecretKeySpec(wraptv.getKey(), 0, wraptv.getKey().length, keyAlg), createSpec(wraptv));
        Key key = c.unwrap(wraptv.getCiphertext(), "AES", Cipher.SECRET_KEY);
        assertArrayEquals(wraptv.getData(), key.getEncoded());
    }

    @Test
    public void wrapUnwrapPublicKey() throws Exception {
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE, false);
        PublicKey key = KeyUtil.loadPublic("EC", kp.getPub());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
        assertEquals(key, unwrapped);

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        try {
            cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to PRIVATE_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
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
        Cipher cipher = getInitCipher(Cipher.WRAP_MODE, false);
        PrivateKey key = KeyUtil.loadPrivate("EC", kp.getPriv());
        byte[] wrapped = cipher.wrap(key);

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        Key unwrapped = cipher.unwrap(wrapped, "EC", Cipher.PRIVATE_KEY);
        assertEquals(key, unwrapped);

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        try {
            cipher.unwrap(wrapped, "EC", Cipher.PUBLIC_KEY);
            fail("Expected unwrap to PUBLIC_KEY to fail");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        try {
            cipher.unwrap(wrapped, "RSA", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (InvalidKeyException e) {
            // Expected.
        }

        cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        try {
            cipher.unwrap(wrapped, "DSNAY", Cipher.PRIVATE_KEY);
            fail("Expected unwrap to wrong alg type");
        } catch (NoSuchAlgorithmException e) {
            // Expected.
        }
    }

    @Test(expected = InvalidKeyException.class)
    public void unwrapDecryptFailure() throws Exception {
        Cipher cipher = getInitCipher(Cipher.UNWRAP_MODE, false);
        cipher.unwrap(new byte[15], "AES", Cipher.SECRET_KEY);
    }


}
