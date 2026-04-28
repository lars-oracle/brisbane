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
import java.security.InvalidAlgorithmParameterException;
import java.security.NoSuchAlgorithmException;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.IvParameterSpec;

import com.oracle.jipher.internal.openssl.CipherCtx;
import com.oracle.jipher.internal.openssl.Rand;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Abstract base class for block-cipher feedback modes such as ECB, CBC, CFB and OFB.
 *
 * <p>This class extends {@link SymmCipher} and implements common handling for
 * buffering, padding, IV validation, and the automatic reset of the underlying
 * OpenSSL {@link CipherCtx} after {@code engineDoFinal}.
 *
 * <p>The nested static subclasses provide concrete implementations for specific
 * algorithms and mode/padding combinations (e.g., {@code Aes128CbcPkcs5Pad},
 * {@code Aes256EcbNoPad}, {@code DESEDE}, etc.).
 *
 * @see SymmCipher
 * @see CipherAlg
 */
public abstract class FeedbackCipher extends SymmCipher {

    private boolean doFinalCalled;

    /**
     * The number of input bytes currently buffered within the EVP_CIPHER_CTX object.
     */
    private int buffered;

    FeedbackCipher(CipherAlg cipherAlg) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(cipherAlg);
        if (cipherAlg instanceof CipherAlg.FixedModePad algModePad) {
            engineSetMode(algModePad.getMode().name());
            engineSetPadding(algModePad.getPadding().name());
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer byteBuffer) {
        throw new IllegalStateException("No AAD accepted");
    }

    @Override
    protected void engineUpdateAAD(byte[] bytes, int i, int i1) {
        throw new IllegalStateException("No AAD accepted");
    }

    @Override
    protected int engineUpdate(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException {
        checkIfInitialized();
        this.updateCalled = true;
        int outputSize = getUpdateOutputSize(inLen);
        if (outputSize > out.length - outOffset) {
            throw new ShortBufferException("Not enough space in output array");
        }
        int outLen = updateInternal(input, inOffset, inLen, out, outOffset, outputSize, this.buffered > 0);
        updateBuffered(inLen);
        return outLen;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        // Special case to allow sequence of: init, doFinal, update..., doFinal as used by JSSE implementation (JDK8-251+).
        if (inLen == 0 && !this.updateCalled && this.ctx != null && this.padding == CipherPadding.NOPADDING) {
            // The effect is as though doFinal was not called at all, ready to update.
            return 0;
        }
        checkIfInitialized();
        this.doFinalCalled = true;
        int outputSize = engineGetOutputSize(inLen);
        int updateOutputSize = getUpdateOutputSize(inLen);

        if ((this.mode == CipherMode.ECB || this.mode == CipherMode.CBC) &&
                (!this.encrypt || this.padding == CipherPadding.NOPADDING)) {
            // blockSize must be a power of two.
            int blockSize = this.cipherAlg.getBlockSize();

            // The total amount of input data remaining to be processed.
            int totalInput = Math.addExact(this.buffered, inLen);

            // Check that the remaining total input data is a multiple of the block size.
            if ((totalInput & (blockSize - 1)) != 0) {
                cleanup();
                throw new IllegalBlockSizeException("Total input data length is not a multiple of the block size");
            }

            // Special case for ECB/PKCS5Padding or CBC/PKCS5Padding decryption.
            if (!this.encrypt && this.padding == CipherPadding.PKCS5PADDING) {

                // Check if it is possible for the output to fit in the supplied buffer (depending on the amount of
                // encrypted plaintext in the padding block) even if the remaining space in the output buffer is less
                // than what engineGetOutputSize() says is required.
                if (outputSize > out.length - outOffset && updateOutputSize <= out.length - outOffset) {
                    // Whether the output buffer is large enough won't be known until the padding block is decrypted.

                    // Buffer to receive the decrypted bytes from the padding block.
                    byte[] finalBytes = new byte[blockSize];

                    // Duplicate the cipher context while keeping a reference to the original.
                    // The decryption is done using the temporary duplicate.
                    // If the supplied buffer was large enough then the cipher context is cleaned after the
                    // original context is restored, otherwise the restored state is left to allow the
                    // caller to retry the doFinal() call with a larger buffer.
                    CipherCtx originalCtx = this.ctx;
                    this.ctx = originalCtx.dup();

                    boolean doCleanup = true;
                    try {
                        int outLen = updateInternal(input, inOffset, inLen, out, outOffset, updateOutputSize, this.buffered > 0);
                        int finalBytesLen = this.ctx.doFinal(finalBytes, 0);
                        if (outLen + finalBytesLen > out.length - outOffset) {
                            // The supplied buffer is not large enough to receive all the plaintext.

                            // Avoid calling cleanup() so that the original context is available for a retry.
                            doCleanup = false;

                            throw new ShortBufferException("Not enough space in output array");
                        }
                        System.arraycopy(finalBytes, 0, out, outOffset + outLen, finalBytesLen);
                        return outLen + finalBytesLen;
                    } finally {
                        // Restore the original cipher context and release the temporary duplicate to the pool.
                        CipherCtx tmpCtx = this.ctx;
                        this.ctx = originalCtx;
                        tmpCtx.release();

                        clearArray(finalBytes);
                        if (doCleanup) {
                            cleanup();
                        }
                    }
                }
            }
        }

        // Check the size of the output buffer before committing to calling cleanup().
        if (outputSize > out.length - outOffset) {
            throw new ShortBufferException("Not enough space in output array");
        }
        try {
            int outLen = updateInternal(input, inOffset, inLen, out, outOffset, updateOutputSize, this.buffered > 0);
            outLen += ctx.doFinal(out, outOffset + outLen);
            return outLen;
        } finally {
            cleanup();
        }
    }

    @Override
    AlgorithmParameterSpec getParamSpec(byte[] iv, AlgorithmParameterSpec spec) {
        return iv != null ? new IvParameterSpec(iv) : spec;
    }

    @Override
    byte[] verifyParams(AlgorithmParameterSpec params, boolean encrypt) throws InvalidAlgorithmParameterException {
        if (params == null) {
            return validateIv(null, encrypt);
        } else if (params instanceof IvParameterSpec) {
            return validateIv(((IvParameterSpec) params).getIV(), encrypt);
        } else {
            throw new InvalidAlgorithmParameterException();
        }
    }

    private byte[] validateIv(byte[] iv, boolean encrypt) throws InvalidAlgorithmParameterException {
        if (iv == null) {
            if (this.mode == CipherMode.ECB) {
                return null;
            }
            if (encrypt) {
                iv = Rand.generate(this.cipherAlg.getBlockSize());
            } else {
                throw new InvalidAlgorithmParameterException("IV parameters required for decryption");
            }
        } else {
            if (this.mode == CipherMode.ECB) {
                throw new InvalidAlgorithmParameterException("No IV expected for ECB.");
            }
            if (iv.length != this.cipherAlg.getBlockSize()) {
                throw new InvalidAlgorithmParameterException("Expected IV of length " + this.cipherAlg.getBlockSize());
            }
        }
        return iv;
    }

    @Override
    Class<? extends AlgorithmParameterSpec> getParameterSpecClass() {
        return IvParameterSpec.class;
    }

    @Override
    int getUpdateOutputSize(int inputLen) {
        int outputSize;
        if (this.mode == CipherMode.ECB || this.mode == CipherMode.CBC) {
            int totalInput = Math.addExact(this.buffered, inputLen);

            // blockSize must be a power of two.
            int blockSize = this.cipherAlg.getBlockSize();

            // outputSize is the input length rounded down to a multiple of the block size.
            outputSize = totalInput & -blockSize;

            // Special case for PKCS5Padding.
            if (this.padding == CipherPadding.PKCS5PADDING && !this.encrypt &&
                    outputSize > 0 && outputSize == totalInput) {
                // If the amount of data to be processed is at least one block and is a
                // multiple of the block size then one block will not be processed and
                // will be retained in the EVP_CIPHER_CTX internal buffer until it can
                // be determined whether that block is the final padding block.
                outputSize -= blockSize;
            }
        } else {
            // mode: CTR, OFB or CFB.
            // These modes behave as a streaming cipher where no data is buffered and the amount
            // of output is equal to the amount of input.
            outputSize = inputLen;
        }
        return outputSize;
    }

    void updateBuffered(int inputLen) {
        if (this.mode == CipherMode.ECB || this.mode == CipherMode.CBC) {
            int processed = Math.addExact(this.buffered, inputLen);

            // blockSize must be a power of two.
            int blockSize = this.cipherAlg.getBlockSize();

            if (this.padding == CipherPadding.PKCS5PADDING && !this.encrypt) {
                // For padded ECB or CBC decrypt the amount of buffered data ranges from 1 to blockSize.
                // Data is processed one block at a time, however up to blockSize bytes beyond a
                // block boundary must be buffered until it can be determined whether the buffered
                // data is the final padding block; if one or more bytes of input is provided beyond a
                // whole block then that block must not be the padding block and can be processed
                // immediately, leaving those extra 1 to blockSize residual bytes buffered in the
                // EVP_CIPHER_CTX.
                this.buffered = processed > 0 ? ((processed - 1) & (blockSize - 1)) + 1 : 0;
            } else {
                // For ECB or CBC encrypt, or non-padded decrypt, data is processed one block at a time.
                // Any residual partial block is buffered in the EVP_CIPHER_CTX until the next
                // update() or doFinal().
                this.buffered = processed & (blockSize - 1);
            }
        }
    }

    @Override
    protected int engineGetOutputSize(int inputLen) {
        int outputSize = getUpdateOutputSize(inputLen);
        if ((this.mode == CipherMode.ECB || this.mode == CipherMode.CBC) && this.padding == CipherPadding.PKCS5PADDING) {
            // blockSize must be a power of two.
            int blockSize = this.cipherAlg.getBlockSize();

            if (this.encrypt) {
                // Round up to the next multiple of the block size to account for the
                // addition of the padding block if doFinal() is called.
                outputSize = Math.addExact(outputSize, blockSize);
            } else {
                // For padded decrypt, up to a whole block of input data is buffered until
                // it can be determined whether that block is the final padding block.
                // If the amount of data to be processed is not a multiple of the block size
                // then doFinal() will fail without producing any output so the current
                // rounded-down value of outputSize applies.
                int totalInput = Math.addExact(this.buffered, inputLen);
                if (outputSize + blockSize == totalInput) {
                    // If the amount of data to be processed is at least one block and is a
                    // multiple of the block size then it is valid for doFinal() to be
                    // called. Adjust the value to account for the maximum amount of
                    // plaintext in the padding block, which is blockSize-1.
                    outputSize += blockSize - 1;
                }
            }
        }
        return outputSize;
    }

    @Override
    String getAlgorithmParametersAlg() {
        return this.cipherAlg.getName();
    }

    @Override
    void cleanup() {
        this.buffered = 0;

        // The JavaDoc for Cipher.doFinal says:
        //   Upon finishing, this method resets this cipher object to the state it was in when previously
        //   initialized via a call to init. That is, the object is reset and available to encrypt or
        //   decrypt (depending on the operation mode that was specified in the call to init) more data.
        //
        // Enable this "auto-reset" for encryption with ECB & CBC modes and for decryption with ECB, CBC, CFB & OFB.
        // Auto-reset is not enabled for encryption due to the potential for key/iv pair reuse, although it is
        // enabled for ECB & CBC modes due to legacy use that relies on the documented behavior.
        // Auto-reset is enabled for decryption, although it is disabled for CTR mode due to an issue resetting
        // a CTR cipher context in OpenSSL.
        if ((!this.encrypt && (this.mode == CipherMode.CFB || this.mode == CipherMode.OFB)) ||
                this.mode == CipherMode.ECB || this.mode == CipherMode.CBC) {
            if (this.initialized && this.doFinalCalled) {
                // Reset the CipherCtx to the state it was in when last initialized.
                this.ctx.reInit();
            }
            this.updateCalled = false;
        } else {
            super.cleanup();
        }
        this.doFinalCalled = false;
    }

    public static final class AES extends FeedbackCipher {
        public AES() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AES());
        }
    }

    public static final class Aes128EcbNoPad extends FeedbackCipher {
        public Aes128EcbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(128, CipherMode.ECB, CipherPadding.NOPADDING));
        }
    }

    public static final class Aes128CbcPkcs5Pad extends FeedbackCipher {
        public Aes128CbcPkcs5Pad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(128, CipherMode.CBC, CipherPadding.PKCS5PADDING));
        }
    }

    public static final class Aes128CfbNoPad extends FeedbackCipher {
        public Aes128CfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(128, CipherMode.CFB, CipherPadding.NOPADDING));
        }
    }
    public static final class Aes128OfbNoPad extends FeedbackCipher {
        public Aes128OfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(128, CipherMode.OFB, CipherPadding.NOPADDING));
        }
    }

    public static final class Aes192EcbNoPad extends FeedbackCipher {
        public Aes192EcbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(192, CipherMode.ECB, CipherPadding.NOPADDING));
        }
    }

    public static final class Aes192CbcPkcs5Pad extends FeedbackCipher {
        public Aes192CbcPkcs5Pad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(192, CipherMode.CBC, CipherPadding.PKCS5PADDING));
        }
    }

    public static final class Aes192CfbNoPad extends FeedbackCipher {
        public Aes192CfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(192, CipherMode.CFB, CipherPadding.NOPADDING));
        }
    }
    public static final class Aes192OfbNoPad extends FeedbackCipher {
        public Aes192OfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(192, CipherMode.OFB, CipherPadding.NOPADDING));
        }
    }

    public static final class Aes256EcbNoPad extends FeedbackCipher {
        public Aes256EcbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(256, CipherMode.ECB, CipherPadding.NOPADDING));
        }
    }

    public static final class Aes256CbcPkcs5Pad extends FeedbackCipher {
        public Aes256CbcPkcs5Pad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(256, CipherMode.CBC, CipherPadding.PKCS5PADDING));
        }
    }

    public static final class Aes256CfbNoPad extends FeedbackCipher {
        public Aes256CfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(256, CipherMode.CFB, CipherPadding.NOPADDING));
        }
    }
    public static final class Aes256OfbNoPad extends FeedbackCipher {
        public Aes256OfbNoPad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesFixed(256, CipherMode.OFB, CipherPadding.NOPADDING));
        }
    }

    public static final class DESEDE extends FeedbackCipher {
        public DESEDE() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.DesEde());
        }
    }

    public static final class DesEdeCbcPkcs5Pad extends FeedbackCipher {
        public DesEdeCbcPkcs5Pad() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.DesEdeFixed(CipherMode.CBC, CipherPadding.PKCS5PADDING));
        }
    }
}
