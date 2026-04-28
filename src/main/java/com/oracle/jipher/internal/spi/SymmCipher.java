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

package com.oracle.jipher.internal.spi;


import java.nio.ByteBuffer;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.CipherSpi;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.ShortBufferException;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.CipherCtx;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Abstract base class for all symmetric cipher implementations in Jipher.
 * <p>
 * It extends {@link CipherSpi} and provides a common implementation for
 * handling OpenSSL based encryption/decryption via {@link CipherCtx}. The class
 * manages cipher algorithm selection ({@link CipherAlg}), mode, padding, IV
 * handling, key validation and the lifecycle of the native {@code EVP_CIPHER_CTX}
 * object. Concrete subclasses such as {@link FeedbackCipher} and
 * {@link RsaCipher} specialise the behaviour for specific algorithms.
 *
 * <p>Key responsibilities:
 * <ul>
 *   <li>Translate JCE {@code CipherSpi} calls to OpenSSL operations.</li>
 *   <li>Validate parameters, key sizes and enforce FIPS requirements.</li>
 *   <li>Manage buffering for block-cipher modes and padding.</li>
 *   <li>Provide a clean {@code cleanup()} method to release native resources.</li>
 * </ul>
 *
 * @see CipherAlg
 * @see CipherMode
 * @see CipherPadding
 * @see CipherCtx
 */
abstract class SymmCipher extends CipherSpi {

    final CipherAlg cipherAlg;
    CipherMode mode = CipherMode.ECB;
    CipherPadding padding = CipherPadding.PKCS5PADDING;

    CipherCtx ctx;

    AlgorithmParameterSpec paramSpec;
    boolean encrypt;
    boolean initialized;
    boolean updateCalled;

    private static final int BOUNCE_BUFFER_SIZE = 16384; // A power of two, so also a multiple of any cipher block or unit size.
    private static final int MAX_BLOCK_SIZE = 16;

    enum BufferOverlapState {
        // Source and destination are either in different byte array instances or are non-overlapping regions
        // of the same byte array.
        DISJOINT,

        // Source and destination start at the same offset of the same byte array and the amount of previously
        // processed data is a multiple of the OpenSSL block size (unit size), i.e. there is no data buffered
        // in the cipher context.
        IN_PLACE,

        // Total input not greater than BOUNCE_BUFFER_SIZE or (zero shift or shift left, and either the
        // amount of processed data is a multiple of the OpenSSL block size (unit size), i.e. there is no
        // data buffered in the cipher context, or the shift left is greater than or equal to 2 * block size)
        // - requiring an input bounce buffer.
        SINGLE_BOUNCE_BUF,

        // Small shift right (right shift not greater than BOUNCE_BUFFER_SIZE, if amount of processed data is a
        // multiple of the OpenSSL block size (unit size), i.e. there is no buffered data in the cipher
        // context, or not greater than BOUNCE_BUFFER_SIZE - (2 * block size), otherwise) or zero shift or shift left
        // that does not meet previous requirements - requiring a pair of consecutive input bounce buffers.
        DOUBLE_BOUNCE_BUF,

        // Large shift right or right shift that does not meet previous requirements. Copy all input data
        // (that is larger than BOUNCE_BUFFER_SIZE) to a temporary buffer.
        COPY_ALL_INPUT
    }

    SymmCipher(CipherAlg baseAlg) {
        this.cipherAlg = baseAlg;
    }

    @Override
    protected void engineSetMode(String s) throws NoSuchAlgorithmException {
        try {
            CipherMode mode = CipherMode.valueOf(s.toUpperCase());
            if (!this.cipherAlg.supportsMode(mode)) {
                throw new NoSuchAlgorithmException("Unsupported mode " + s);
            }
            this.mode = mode;
        } catch (IllegalArgumentException e) {
            throw new NoSuchAlgorithmException("Unsupported mode " + s);
        }
    }

    @Override
    protected void engineSetPadding(String s) throws NoSuchPaddingException {
        try {
            CipherPadding padding = "PKCS7PADDING".equalsIgnoreCase(s) ?
                CipherPadding.PKCS5PADDING : CipherPadding.valueOf(s.toUpperCase());
            if (!this.cipherAlg.supportsPadding(this.mode, padding)) {
                throw new NoSuchPaddingException("Unsupported padding " + s + " for mode " + this.mode);
            }
            this.padding = padding;
        } catch (IllegalArgumentException e) {
            throw new NoSuchPaddingException("Unsupported padding " + s);
        }

    }

    @Override
    protected int engineGetKeySize(Key key) {
        byte[] encoded = key.getEncoded();
        clearArray(encoded);
        return encoded.length * 8;
    }

    @Override
    protected void engineInit(int cipherMode, Key key, SecureRandom secureRandom) throws InvalidKeyException {
        try {
            engineInit(cipherMode, key, (AlgorithmParameterSpec) null, secureRandom);
        } catch (InvalidAlgorithmParameterException e) {
            throw new InvalidParameterException(e.getMessage());
        }
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameters algorithmParameters, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        engineInit(cipherMode, key, convertParamsToSpec(algorithmParameters), secureRandom);
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        if (this.paramSpec == null) {
            return null;
        }
        try {
            AlgorithmParameters algParams = AlgorithmParameters.getInstance(getAlgorithmParametersAlg(), InternalProvider.get());
            algParams.init(this.paramSpec);
            return algParams;
        } catch (InvalidParameterSpecException | NoSuchAlgorithmException e) {
            throw new ProviderException("Unexpectedly, could not get parameters", e);
        }
    }

    abstract String getAlgorithmParametersAlg();

    abstract Class<? extends AlgorithmParameterSpec> getParameterSpecClass();

    private AlgorithmParameterSpec convertParamsToSpec(AlgorithmParameters params) throws InvalidAlgorithmParameterException {
        if (params == null) {
            return null;
        }
        try {
            return params.getParameterSpec(getParameterSpecClass());
        } catch (InvalidParameterSpecException e) {
            throw new InvalidAlgorithmParameterException("AlgorithmParameters invalid for algorithm, expected to retrieve " + getParameterSpecClass().getName());
        }
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        initInternal(key, algorithmParameterSpec, cipherMode == Cipher.ENCRYPT_MODE || cipherMode == Cipher.WRAP_MODE);
    }

    @Override
    protected byte[] engineWrap(Key key) throws IllegalBlockSizeException {
        byte[] keyBytes = key.getEncoded();
        try {
            return engineDoFinal(keyBytes, 0, keyBytes.length);
        } catch (BadPaddingException e) {
            throw new IllegalBlockSizeException(e.getMessage());
        } finally {
            clearArray(keyBytes);
        }
    }

    @Override
    protected Key engineUnwrap(byte[] wrappedKey, String keyAlg, int wrappedKeyType) throws InvalidKeyException, NoSuchAlgorithmException {
        byte[] keyBytes = null;
        try {
            keyBytes = engineDoFinal(wrappedKey, 0, wrappedKey.length);
            return WrapUtil.createKey(keyAlg, wrappedKeyType, keyBytes);
        } catch (BadPaddingException | IllegalBlockSizeException e) {
            throw new InvalidKeyException("Failed to unwrap valid key", e);
        } finally {
            clearArray(keyBytes);
        }
    }

    abstract byte[] verifyParams(AlgorithmParameterSpec spec, boolean encrypt) throws InvalidAlgorithmParameterException;

    private void initInternal(Key key, AlgorithmParameterSpec params, boolean encrypt) throws InvalidKeyException, InvalidAlgorithmParameterException {
        cleanup();

        byte[] keyData = verifyKeyData(key);
        try {
            Fips.enforcement().checkAlg(encrypt ? CryptoOp.ENCRYPT_SYM : CryptoOp.DECRYPT_SYM, this.cipherAlg.getName());
            Fips.enforcement().checkStrength(encrypt ? CryptoOp.ENCRYPT_SYM : CryptoOp.DECRYPT_SYM, this.cipherAlg.getName(), keyData.length * 8);
            byte[] ivBytes = verifyParams(params, encrypt);
            if (this.ctx == null) {
                this.ctx = new CipherCtx();
            }
            this.ctx.init(this.cipherAlg.getAlg(keyData.length * 8, this.mode),
                this.padding == CipherPadding.PKCS5PADDING, encrypt, keyData, ivBytes);
            this.paramSpec = getParamSpec(ivBytes, params);
            this.encrypt = encrypt;
            this.initialized = true;
            this.updateCalled = false;
        } catch (FIPSPolicyException e) {
            throw new InvalidKeyException(e.getMessage(), e);
        } finally {
            clearArray(keyData);
            if (!this.initialized) {
                releaseCtx();
            }
        }
    }

    abstract AlgorithmParameterSpec getParamSpec(byte[] iv, AlgorithmParameterSpec spec);

    private byte[] verifyKeyData(Key key) throws InvalidKeyException {
        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey permitted.");
        }
        byte[] encoded = key.getEncoded();
        try {
            this.cipherAlg.validateKeySize(encoded.length);
            byte[] tmp = encoded;
            encoded = null;
            return tmp;
        } finally {
            clearArray(encoded);
        }
    }

    @Override
    protected int engineUpdate(ByteBuffer input, ByteBuffer output) throws ShortBufferException {
        return super.engineUpdate(input, output);
    }

    @Override
    protected byte[] engineUpdate(byte[] input, int inOffset, int inLen) {
        byte[] out = new byte[getUpdateOutputSize(inLen)];
        try {
            int len = engineUpdate(input, inOffset, inLen, out, 0);
            if (len == out.length) {
                byte[] tmp = out;
                out = null;
                return tmp;
            }
            return Arrays.copyOf(out, len);
        } catch (ShortBufferException e) {
            // Should not happen
            throw new AssertionError("Internal error: Unexpected ShortBufferException", e);
        } finally {
            clearArray(out);
        }
    }

    /*
     * The caller should make sure that none of the offset or length parameters are negative.
     */
    int updateInternal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset, int outLen, boolean bufferedData) throws ShortBufferException {
        boolean clearBounceBuffer = false;
        BufferOverlapState overlapState = bufferOverlapState(input, inOffset, inLen, out, outOffset, outLen, bufferedData);
        if (overlapState != BufferOverlapState.DISJOINT && overlapState != BufferOverlapState.IN_PLACE) {
            input = Arrays.copyOfRange(input, inOffset, inOffset + inLen);
            inOffset = 0;

            // Clear the bounce-buffer after use when encrypting.
            clearBounceBuffer = this.encrypt;
        }
        try {
            return updateInternal(input, inOffset, inLen, out, outOffset);
        } finally {
            if (clearBounceBuffer) {
                Util.clearArray(input);
            }
        }
    }

    int updateInternal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException {
        if (inLen > 0) {
            return ctx.update(input, inOffset, inLen, out, outOffset);
        }
        return 0;
    }

    abstract int getUpdateOutputSize(int inputLen);

    /*
     * The caller should make sure that none of the offset or length parameters are negative.
     */
    static boolean isOverlapping(byte[] input, int inOffset, int inLen, byte[] out, int outOffset, int outLen) {
        return input == out && outOffset < Math.addExact(inOffset, inLen) && inOffset < Math.addExact(outOffset, outLen);
    }

    /*
     * The caller should make sure that none of the offset or length parameters are negative.
     */
    static BufferOverlapState bufferOverlapState(byte[] input, int inOffset, int inLen, byte[] out, int outOffset, int outLen, boolean bufferedData) {
        if (!isOverlapping(input, inOffset, inLen, out, outOffset, outLen)) {
            return BufferOverlapState.DISJOINT;
        }
        if (inOffset == outOffset && !bufferedData) {
            return BufferOverlapState.IN_PLACE;
        }
        if (inLen <= BOUNCE_BUFFER_SIZE ||
                (outOffset <= inOffset && (!bufferedData || (inOffset - outOffset) >= 2 * MAX_BLOCK_SIZE))) {
            return BufferOverlapState.SINGLE_BOUNCE_BUF;
        }
        if (outOffset <= inOffset ||
                (!bufferedData || (outOffset - inOffset) <= BOUNCE_BUFFER_SIZE - 2 * MAX_BLOCK_SIZE)) {
            return BufferOverlapState.DOUBLE_BOUNCE_BUF;
        }
        return BufferOverlapState.COPY_ALL_INPUT;
    }

    @Override
    protected byte[] engineDoFinal(byte[] input, int inOffset, int inLen) throws IllegalBlockSizeException, BadPaddingException {
        byte[] out = new byte[engineGetOutputSize(inLen)];
        try {
            int len = engineDoFinal(input, inOffset, inLen, out, 0);
            if (len == out.length) {
                byte[] tmp = out;
                out = null;
                return tmp;
            }
            return Arrays.copyOf(out, len);
        } catch (ShortBufferException e) {
            // Should not happen
            throw new AssertionError("Internal error: Unexpected ShortBufferException", e);
        } finally {
            clearArray(out);
        }
    }

    @Override
    protected int engineDoFinal(ByteBuffer input, ByteBuffer output) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        return super.engineDoFinal(input, output);
    }

    @Override
    protected byte[] engineGetIV() {
        try {
            return verifyParams(this.paramSpec, this.encrypt);
        } catch (InvalidAlgorithmParameterException e) {
            return null;
        }
    }

    @Override
    protected int engineGetBlockSize() {
        return this.cipherAlg.getBlockSize();
    }

    void cleanup() {
        // Release the CipherCtx, which will release the EVP_CIPHER_CTX object to the EVP_CIPHER_CTX object
        // pool and cause the key and iv to be zeroed now rather than wait for the native object to be
        // cleaned when the enclosing java object is determined to be unreachable.
        releaseCtx();
        this.initialized = false;
        this.updateCalled = false;
    }

    private void releaseCtx() {
        CipherCtx ctxToRelease = this.ctx;
        if (ctxToRelease != null) {
            this.ctx = null;
            ctxToRelease.release();
        }
    }

    void checkIfInitialized() {
        if (!this.initialized) {
            throw new IllegalStateException("Not initialized");
        }
    }
}
