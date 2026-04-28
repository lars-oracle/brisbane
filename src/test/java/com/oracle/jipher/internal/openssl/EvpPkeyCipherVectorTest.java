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

package com.oracle.jipher.internal.openssl;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.security.spec.KeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assume.assumeTrue;

/**
 * Tests
 *     EVP_PKEY_encrypt_init_ex, EVP_PKEY_encrypt
 *     EVP_PKEY_decrypt_init_ex, EVP_PKEY_decrypt
 *  using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpPkeyCipherVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(AsymCipherTestVector.class);
    }

    private final String alg;
    private final KeySpec privateKeySpec;
    private final KeySpec publicKeySpec;
    private final byte[] plaintext;
    private final byte[] ciphertext;
    private final String mdAlg;
    private final String mgfMdAlg;
    private final byte[] psourceVal;

    private int keyBits;
    private EVP_PKEY_CTX encryptorCtx;
    private EVP_PKEY_CTX decryptorCtx;

    static String getOpenSslMdAlg(String alg) {
        String digest = alg.replace("SHA-", "SHA").replace("SHA", "SHA-");
        return switch (digest) {
            case "SHA-1" -> EVP_MD.DIGEST_NAME_SHA1;
            case "SHA-224" -> EVP_MD.DIGEST_NAME_SHA2_224;
            case "SHA-256" -> EVP_MD.DIGEST_NAME_SHA2_256;
            case "SHA-384" -> EVP_MD.DIGEST_NAME_SHA2_384;
            case "SHA-512" -> EVP_MD.DIGEST_NAME_SHA2_512;
            default -> throw new AssertionError();
        };
    }

    static String getAlgMd(String alg) {
        int startIndex = alg.toUpperCase().indexOf("OAEP");
        int endIndex = alg.toUpperCase().indexOf("ANDMGF1");
        if (startIndex == -1 || endIndex == -1) {
            return null;
        }
        return alg.substring(startIndex + 8, endIndex);
    }

    static boolean hasPadding(String alg) {
        return !alg.toUpperCase().contains("NOPADDING");
    }

    static boolean isOaep(String alg) {
        return alg.toUpperCase().contains("OAEP");
    }

    static boolean isDeterministic(String alg) {
        return !alg.toUpperCase().contains("OAEP");
    }

    public EvpPkeyCipherVectorTest(String description, AsymCipherTestVector tv) throws Exception {
        this.alg = tv.getAlg();
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        this.privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.publicKeySpec = KeyUtil.getPublicKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.plaintext = tv.getData();
        this.ciphertext = tv.getCiphertext();
        this.mdAlg = getAlgMd(this.alg) != null ? getOpenSslMdAlg(getAlgMd(this.alg)) : EVP_MD.DIGEST_NAME_SHA1; // Default
        if (tv.getParams() != null) {
            AsymCipherTestVector.AsymParams params = tv.getParams();
            this.mgfMdAlg = getOpenSslMdAlg(params.mgfAlg());
            this.psourceVal = params.psourceVal();
        } else {
            // Defaults
            this.mgfMdAlg =  EVP_MD.DIGEST_NAME_SHA1;
            this.psourceVal = new byte[0];
        }
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();

        Version fipsProviderVersion = new Version(FipsProviderInfoUtil.getVersionString());

        this.keyBits = ((RSAPrivateCrtKeySpec) this.privateKeySpec).getModulus().bitLength();

        EVP_PKEY publicKey = KeyUtil.loadPublic(this.publicKeySpec, this.libCtx, this.testArena);
        encryptorCtx = libCtx.newPkeyCtx(publicKey,null, this.testArena);
        encryptorCtx.encryptInit();

        EVP_PKEY privateKey = KeyUtil.loadPrivate(this.privateKeySpec, this.libCtx, this.testArena);
        decryptorCtx = libCtx.newPkeyCtx(privateKey, null, this.testArena);
        decryptorCtx.decryptInit();

        if (this.alg.contains("OAEPWith") && !(this.alg.contains("OAEPWithSHA-1") || this.alg.contains("OAEPWithSHA1"))) {
            // OpenSSL commit 4c172a2da4c88f52d67113da2374e61812d43be5 fixed a bug to ensure that the MGF1 digest
            // is set correctly. This bug fix first appeared in 3.0.7 (Feb 1, 2023) ?? 3.1.0 (Mar 14, 2023)
            assumeTrue("Bug fix to ensure that the MGF1 digest is set correctly first appeared in 3.0.7",
                    fipsProviderVersion.compareTo(Version.of("3.0.7")) >= 0);
        }
    }

    @Test
    public void encryptDecrypt()  throws Exception {
        setPadding(encryptorCtx);
        if (isOaep(this.alg)) {
            setOaepParams(encryptorCtx);
        }

        byte[] input;
        if (hasPadding(this.alg)) {
            input = this.plaintext;
        } else {
            // Pad the array with zeros.
            input = new byte[this.keyBits / 8];
            System.arraycopy(this.plaintext, 0, input, input.length - this.plaintext.length, this.plaintext.length);
        }

        int outLen = encryptorCtx.encrypt(input, 0, input.length, null, 0);
        byte[] output = new byte[outLen];
        outLen = encryptorCtx.encrypt(input, 0, input.length, output, 0);
        if (outLen != output.length) {
            output = Arrays.copyOf(output, outLen);
        }

        if (isDeterministic(this.alg)) {
            assertArrayEquals(this.ciphertext, output);
        }

        doDecrypt(output);
    }

    @Test
    public void decrypt()  throws Exception {
        doDecrypt(this.ciphertext);
    }

    private void doDecrypt(byte[] input) throws Exception {
        setPadding(decryptorCtx);
        if (isOaep(this.alg)) {
            setOaepParams(decryptorCtx);
        }

        int outLen = decryptorCtx.decrypt(input, 0, input.length, null, 0);
        byte[] output = new byte[outLen];
        outLen = decryptorCtx.decrypt(input, 0, input.length, output, 0);
        if (outLen != output.length) {
            output = Arrays.copyOf(output, outLen);
        }

        if (hasPadding(this.alg)) {
            assertArrayEquals(this.plaintext, output);
        } else {
            // Expect the decrypted data to be padded with zeros if the plaintext was shorter than blocksize.
            // So use BigIntegers to compare.
            if (this.plaintext.length == output.length) {
                assertArrayEquals(this.plaintext, output);
            } else {
                BigInteger plaintextInt = new BigInteger(1, this.plaintext);
                BigInteger outputInt = new BigInteger(1, output);
                assertEquals(plaintextInt, outputInt);
            }
        }
    }

    @Test
    public void encryptDecryptByteBuffer() throws Exception {
        encryptDecryptByteBuffer(false);
    }

    @Test
    public void encryptDecryptByteBufferDirect() throws Exception {
        encryptDecryptByteBuffer(true);
    }

    @Test
    public void decryptByteBuffer() throws Exception {
        decryptByteBuffer(false);
    }

    @Test
    public void decryptByteBufferDirect() throws Exception {
        decryptByteBuffer(true);
    }

    void encryptDecryptByteBuffer(boolean direct) throws Exception {
        setPadding(encryptorCtx);
        if (isOaep(this.alg)) {
            setOaepParams(this.encryptorCtx);
        }

        ByteBuffer input;
        if (hasPadding(this.alg)) {
            input = direct ? ByteBuffer.wrap(this.plaintext) : copyDirect(this.plaintext);
        } else {
            // Pad the array with zeros.
            byte[] inputBytes = new byte[this.keyBits / 8];
            System.arraycopy(this.plaintext, 0, inputBytes, inputBytes.length - this.plaintext.length, this.plaintext.length);
            input = direct ? ByteBuffer.wrap(inputBytes) : copyDirect(inputBytes);
        }

        int outLen = encryptorCtx.encrypt(input, null);
        ByteBuffer output = direct ? ByteBuffer.allocateDirect(outLen) : ByteBuffer.allocate(outLen);
        outLen = encryptorCtx.encrypt(input, output);
        assertEquals(outLen, output.position());
        assertFalse(output.hasRemaining());

        if (isDeterministic(this.alg)) {
            byte[] encryptedBytes = new byte[output.position()];
            output.flip().get(encryptedBytes);
            assertArrayEquals(this.ciphertext, encryptedBytes);
        }

        doDecrypt(output.flip().rewind(), direct);
    }

    void decryptByteBuffer(boolean direct) throws Exception {
        ByteBuffer input = direct ? ByteBuffer.wrap(this.ciphertext) : copyDirect(this.ciphertext);
        doDecrypt(input, direct);
    }

    void doDecrypt(ByteBuffer input, boolean direct) throws Exception {
        setPadding(decryptorCtx);
        if (isOaep(this.alg)) {
            setOaepParams(decryptorCtx);
        }

        int outLen = decryptorCtx.decrypt(input, null);
        ByteBuffer output = direct ? ByteBuffer.allocateDirect(outLen) : ByteBuffer.allocate(outLen);
        outLen = decryptorCtx.decrypt(input, output);
        assertEquals(outLen, output.position());

        if (hasPadding(this.alg)) {
            byte[] decryptedBytes = new byte[output.position()];
            output.flip().get(decryptedBytes);
            assertArrayEquals(this.plaintext, decryptedBytes);
        } else {
            // Expect the decrypted data to be padded with zeros if the plaintext was shorter than blocksize.
            assertFalse(output.hasRemaining());
            // So use BigIntegers to compare.
            if (this.plaintext.length == output.position()) {
                byte[] decryptedBytes = new byte[plaintext.length];
                output.flip().get(decryptedBytes);
                assertArrayEquals(this.plaintext, decryptedBytes);
            } else {
                byte[] decryptedBytes = new byte[output.position()];
                output.flip().get(decryptedBytes);
                BigInteger plaintextInt = new BigInteger(1, this.plaintext);
                BigInteger decryptedInt = new BigInteger(1, decryptedBytes);
                assertEquals(plaintextInt, decryptedInt);
            }
        }
    }

    public void setPadding(EVP_PKEY_CTX pkeyCtx) {
        OSSL_PARAM param = OSSL_PARAM.of(EVP_PKEY.PKEY_PARAM_PAD_MODE, isOaep(this.alg) ?
                EVP_PKEY.PKEY_RSA_PAD_MODE_OAEP : EVP_PKEY.PKEY_RSA_PAD_MODE_NONE);
        pkeyCtx.setParams(param);
    }

    public void setOaepParams(EVP_PKEY_CTX pkeyCtx) {
        pkeyCtx.setParams(OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_DIGEST, this.mdAlg),
                OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_MGF1_DIGEST, this.mgfMdAlg),
                OSSL_PARAM.of(EVP_PKEY.ASYM_CIPHER_PARAM_OAEP_LABEL, this.psourceVal));
    }

    ByteBuffer copyDirect(byte[] bytes) {
        ByteBuffer buf = ByteBuffer.allocateDirect(bytes.length);
        buf.put(bytes);
        return buf.clear();
    }
}
