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
import java.security.NoSuchAlgorithmException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import javax.crypto.AEADBadTagException;
import javax.crypto.BadPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.ShortBufferException;
import javax.crypto.spec.GCMParameterSpec;

import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.common.Util;

/**
 * Abstract base class for AEAD (Authenticated Encryption with Associated Data)
 * cipher implementations. It extends {@link SymmCipher} and adds support for:
 * <ul>
 *   <li>Processing additional authenticated data (AAD).</li>
 *   <li>Managing authentication tags for encryption and decryption.</li>
 *   <li>Automatic IV generation for modes such as GCM.</li>
 *   <li>Buffering ciphertext in non-streaming decryption mode.</li>
 * </ul>
 * Concrete subclasses (e.g., {@code AesGcm}) provide specific algorithm
 * configurations.
 *
 * @see SymmCipher
 * @see CipherAlg
 */
public abstract class AeadCipher extends SymmCipher {

    byte[] tag;
    int fillOffset;
    boolean ivGenerated;

    private static final int CONSOLIDATION_BUF_SIZE = 4096;
    // Buffers to hold ciphertext data when updating for decryption in the default non-streaming mode.
    private final List<byte[]> ctBufList = new ArrayList<>();
    // A buffer used to consolidate smaller chunks of data into larger byte arrays.
    private ByteBuffer ctConsolidationBuf;

    // The total content of both ctBufList and ctConsolidationBuf.
    int ctBufferLen = 0;

    AeadCipher(CipherAlg cipherAlg) {
        super(cipherAlg);
    }

    void ensureParamSpec() {
        // Do nothing
    }

    @Override
    protected AlgorithmParameters engineGetParameters() {
        ensureParamSpec();
        return super.engineGetParameters();
    }

    @Override
    protected byte[] engineGetIV() {
        ensureParamSpec();
        return super.engineGetIV();
    }

    @Override
    protected void engineUpdateAAD(byte[] aad, int off, int len) {
        if (this.updateCalled) {
            throw new IllegalStateException("AAD must be supplied before encryption/decryption starts");
        }
        checkIfInitialized();
        this.ctx.updateAad(aad, off, len);
        if (this.encrypt && len > 0) {
            this.ivGenerated = true;
        }
    }

    @Override
    protected void engineUpdateAAD(ByteBuffer byteBuffer) {
        byte[] bout = new byte[byteBuffer.remaining()];
        byteBuffer.get(bout);
        engineUpdateAAD(bout, 0, bout.length);
    }

    @Override
    protected int engineUpdate(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException {
        checkIfInitialized();
        this.updateCalled = true;
        int updateOutputSize = getUpdateOutputSize(inLen);
        if (updateOutputSize > out.length - outOffset) {
            throw new ShortBufferException("Not enough space in output array");
        }
        if (this.encrypt || ToolkitProperties.getJipherCipherAeadStreamValue()) {
            int count = updateInternal(input, inOffset, inLen, out, outOffset, updateOutputSize, this.fillOffset > 0);
            if (this.encrypt && inLen > 0) {
                this.ivGenerated = true;
            }
            return count;
        } else {
            // Default non-streaming decrypt mode. Ciphertext input is buffered in ciphertextBuffer.
            appendToCiphertextBuf(input, inOffset, inLen);
            return 0;
        }
    }

    void appendToCiphertextBuf(byte[] input, int inOffset, int inLen) {
        if (inLen > 0) {
            try {
                this.ctBufferLen = Math.addExact(this.ctBufferLen, inLen);
            } catch (ArithmeticException ex) {
                throw new ProviderException("JipherJCE provider only supports buffering of AES/GCM ciphertext up to " +
                        Integer.MAX_VALUE + " bytes in size", ex);
            }
            if (inLen <= CONSOLIDATION_BUF_SIZE / 4) {
                // Use the consolidation buffer.
                if (this.ctConsolidationBuf == null) {
                    this.ctConsolidationBuf = ByteBuffer.allocate(CONSOLIDATION_BUF_SIZE);
                } else if (inLen > this.ctConsolidationBuf.remaining()) {
                    // There is not enough room left in the consolidation buffer.
                    flushCiphertextConsolidationBuf();
                }
                this.ctConsolidationBuf.put(input, inOffset, inLen);
            } else {
                flushCiphertextConsolidationBuf();
                this.ctBufList.add(Arrays.copyOfRange(input, inOffset, inOffset + inLen));
            }
        }
    }

    // Flush the consolidation buffer content to ctBufList.
    void flushCiphertextConsolidationBuf() {
        if (this.ctConsolidationBuf != null && this.ctConsolidationBuf.position() > 0) {
            byte[] buf = new byte[this.ctConsolidationBuf.position()];
            this.ctConsolidationBuf.rewind();
            this.ctConsolidationBuf.get(buf);
            this.ctConsolidationBuf.rewind();
            this.ctBufList.add(buf);
        }
    }

    void clearCiphertextBuf() {
        this.ctBufList.clear();
        this.ctConsolidationBuf = null;
        this.ctBufferLen = 0;
    }

    @Override
    int updateInternal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException {
        int outLen;
        if (this.encrypt) {
            outLen = super.updateInternal(input, inOffset, inLen, out, outOffset);
        } else {
            // Streaming decrypt mode. Decrypted plaintext is available before being authenticated.
            // Need to keep track of last 'tagLen' bytes as this could be authentication tag.
            // case: inLen >= tagLen: update tag, update input, copy tag
            // case: inLen <= tagLen - fillOffset: copy tag
            // case: inLen > tagLen - fillOffset, inLen < tagLen OR inLen + fillOffset > tagLen, inLen < tagLen
            if (inLen <= this.tag.length - this.fillOffset) {
                outLen = 0;
                System.arraycopy(input, inOffset, this.tag, this.fillOffset, inLen);
                this.fillOffset += inLen;
            } else if (inLen >= this.tag.length) {
                // Update buffered bytes of tag
                outLen = super.updateInternal(this.tag, 0, this.fillOffset, out, outOffset);
                // Update all but last tagLen bytes of input
                outLen += super.updateInternal(input, inOffset, inLen - this.tag.length, out, outOffset + outLen);
                // Buffer last tagLen bytes of input as tag
                System.arraycopy(input, inOffset + inLen - this.tag.length, this.tag, 0, this.tag.length);
                this.fillOffset = this.tag.length;
            } else {
                int bytesToUpdate = this.fillOffset + inLen - this.tag.length;
                // Update bytesToUpdate bytes from tag
                outLen = super.updateInternal(this.tag, 0, bytesToUpdate, out, outOffset);
                // Shift the remaining bytes of tag to beginning of tag buffer
                this.fillOffset -= bytesToUpdate;
                System.arraycopy(this.tag, bytesToUpdate, tag, 0, this.fillOffset);
                // Copy input to end of tag
                System.arraycopy(input, inOffset, this.tag, this.fillOffset, inLen);
                this.fillOffset += inLen;
            }
        }
        return outLen;
    }

    @Override
    protected int engineDoFinal(byte[] input, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException, IllegalBlockSizeException, BadPaddingException {
        checkIfInitialized();

        // Check the size of the output buffer before committing to calling cleanup().
        int outputSize = engineGetOutputSize(inLen);
        if (outputSize > out.length - outOffset) {
            throw new ShortBufferException("Not enough space in output array");
        }
        try {
            int outLen = 0;
            if (this.encrypt) {
                if (inLen > 0) {
                    outLen = updateInternal(input, inOffset, inLen, out, outOffset, inLen, false);
                }
                outLen += this.ctx.doFinal(out, outOffset);
                this.ivGenerated = true;
                if (outLen + this.tag.length > out.length - outOffset) {
                    throw new ProviderException("Internal error: Not enough space in output buffer.");
                }
                this.ctx.getAuthTag(out, outOffset + outLen, this.tag.length);
                outLen += this.tag.length;

                // If paramSpec is null then retrieve the generated IV from ctx before cleanup() is called.
                ensureParamSpec();
            } else if (ToolkitProperties.getJipherCipherAeadStreamValue()) {
                // Streaming decrypt mode. Decrypted plaintext is available before being authenticated.
                if (inLen + this.fillOffset < this.tag.length) {
                    throw new AEADBadTagException("Insufficient input data.");
                }
                if (inLen > 0) {
                    int updateOutputSize = getUpdateOutputSize(inLen);
                    outLen = updateInternal(input, inOffset, inLen, out, outOffset, updateOutputSize, this.fillOffset > 0);
                }
                ctx.setAuthTag(this.tag, 0, this.tag.length);
                try {
                    outLen += this.ctx.doFinal(out, outOffset + outLen);
                } catch (BadPaddingException | IllegalBlockSizeException e) {
                    // Throw ProviderException instead of AEADBadTagException as the close() methods of
                    // javax.crypto.CipherInputStream and javax.crypto.CipherOutputStream catch and ignore
                    // BadPaddingException, which is a superclass of AEADBadTagException.
                    throw new ProviderException("Authentication tag does not match.");
                }
            } else {
                // Default non-streaming decrypt mode. Ciphertext input is buffered in ciphertextBuffer.
                if (Math.addExact(this.ctBufferLen, inLen) < this.tag.length) {
                    throw new AEADBadTagException("Insufficient input data.");
                }

                if (inLen > 0 && isOverlapping(input, inOffset, inLen, out, outOffset, outputSize)) {
                    // The output buffer overlaps with the input buffer. Move all input to
                    // this.ciphertextBuffer.
                    appendToCiphertextBuf(input, inOffset, inLen);
                    inLen = 0;
                }

                // Copy the tag data from the end of the input and/or this.ciphertextBuffer to this.tag.
                if (inLen >= this.tag.length) {
                    // All tag data comes from input.
                    System.arraycopy(input, inOffset + inLen - this.tag.length, this.tag, 0, this.tag.length);
                    inLen -= this.tag.length;
                } else {
                    // Some tag data comes from input and the rest from this.ciphertextBuffer.
                    // Place all input (if any) at the end of this.tag.
                    if (inLen > 0) {
                        System.arraycopy(input, inOffset, this.tag, this.tag.length - inLen, inLen);
                    }
                    int remaining = this.tag.length - inLen;
                    inLen = 0;

                    // Loop over the byte arrays in this.ciphertextBuffer, starting at the end, and
                    // copy data to this.tag until remaining == 0.
                    flushCiphertextConsolidationBuf();
                    int i = this.ctBufList.size();
                    for (;;) {
                        byte[] buf = this.ctBufList.remove(--i);
                        int n = Math.min(buf.length, remaining);
                        this.ctBufferLen -= n;
                        remaining -= n;
                        System.arraycopy(buf, buf.length - n, this.tag, remaining, n);
                        if (remaining == 0) {
                            if (n < buf.length) {
                                // Append the remaining data in buf back on to this.ciphertextBuffer.
                                appendToCiphertextBuf(buf, 0, buf.length - n);
                            }
                            break;
                        }
                    }
                }

                // Default to clearing the contents of the output buffer.
                boolean clearOutputBuffer = true;
                try {
                    flushCiphertextConsolidationBuf();
                    for (byte[] buf : this.ctBufList) {
                        outLen += ctx.update(buf, 0, buf.length, out, outOffset + outLen);
                    }
                    if (inLen > 0) {
                        outLen += ctx.update(input, inOffset, inLen, out, outOffset + outLen);
                    }
                    ctx.setAuthTag(this.tag, 0, this.tag.length);
                    try {
                        outLen += this.ctx.doFinal(out, outOffset + outLen);
                    } catch (BadPaddingException | IllegalBlockSizeException e) {
                        throw new AEADBadTagException("Authentication tag does not match.");
                    }

                    // No exception occurred. Disable clearing of the output buffer.
                    clearOutputBuffer = false;
                } finally {
                    if (clearOutputBuffer) {
                        // Clear all plaintext in the output buffer.
                        Arrays.fill(out, outOffset, outOffset + outputSize, (byte) 0);
                    }
                }
            }
            return outLen;
        } finally {
            cleanup();
        }
    }

    @Override
    void cleanup() {
        super.cleanup();
        this.updateCalled = false;
        this.ivGenerated = false;
        Util.clearArray(this.tag);
        this.fillOffset = 0;
        clearCiphertextBuf();
    }

    public static final class AesGcm extends Gcm {
        public AesGcm() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesGcm());
        }
    }

    public static final class Aes128Gcm extends Gcm {
        public Aes128Gcm() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesGcm(16));
        }
    }
    public static final class Aes192Gcm extends Gcm {
        public Aes192Gcm() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesGcm(24));
        }
    }
    public static final class Aes256Gcm extends Gcm {
        public Aes256Gcm() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(new CipherAlg.AesGcm(32));
        }
    }

    static abstract class Gcm extends AeadCipher {

        private static final int DEFAULT_TAG_LEN_BYTES = 16;

        Gcm(CipherAlg alg) throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(alg);
            engineSetMode("GCM");
            engineSetPadding("NoPadding");
        }

        @Override
        void ensureParamSpec() {
            if (this.ctx != null && this.encrypt && this.paramSpec == null) {
                // Retrieve the IV from OpenSSL and store it as a new GCMParameterSpec.
                try {
                    boolean generateIv = !this.ivGenerated;
                    if (generateIv) {
                        // The GCM IV hasn't been generated yet.
                        // FIPS 140 requires that the GCM IV be generated within the FIPS boundary
                        // thus we must force OpenSSL to generate it. This is done by calling
                        // CipherCtx::doFinal, however doing so will require that we retrieve the IV
                        // and then re-init the EVP_CIPHER_CTX with the retrieved IV in order to
                        // prepare the cipher to receive input data.
                        this.ctx.doFinal(new byte[16], 0);
                    }
                    byte[] iv = this.ctx.getIv();
                    if (generateIv) {
                        // Re-init the EVP_CIPHER_CTX with the retrieved IV.
                        this.ctx.reInit(iv);
                    }
                    this.paramSpec = new GCMParameterSpec(this.tag.length * 8, iv);
                } catch (IllegalBlockSizeException | BadPaddingException | IllegalStateException | ShortBufferException e) {
                    // Ignore any exceptions resulting from the CipherCtx not being properly initialized.
                }
            }
        }

        @Override
        int getUpdateOutputSize(int inputLen) {
            if (this.encrypt) {
                return inputLen;
            } else if (ToolkitProperties.getJipherCipherAeadStreamValue()) {
                return Math.max(0, Math.addExact(this.fillOffset, inputLen) - this.tag.length);
            } else {
                return 0;
            }
        }

        @Override
        protected int engineGetOutputSize(int inputLen) {
            if (this.encrypt) {
                return Math.addExact(inputLen, this.tag.length);
            } else {
                int buffered = ToolkitProperties.getJipherCipherAeadStreamValue() ? this.fillOffset : this.ctBufferLen;
                return Math.max(0, Math.addExact(buffered, inputLen) - this.tag.length);
            }
        }

        @Override
        String getAlgorithmParametersAlg() {
            return "GCM";
        }

        @Override
        AlgorithmParameterSpec getParamSpec(byte[] iv, AlgorithmParameterSpec spec) {
            if (spec != null || iv == null) {
                return spec;
            }
            return new GCMParameterSpec(this.tag.length * 8, iv);
        }

        @Override
        byte[] verifyParams(AlgorithmParameterSpec params, boolean encrypt) throws InvalidAlgorithmParameterException {
            if (params instanceof GCMParameterSpec gcmSpec) {
                byte[] iv = gcmSpec.getIV();
                if (iv.length == 0) {
                    throw new InvalidAlgorithmParameterException("Invalid GCM IV.");
                }
                int tLen = gcmSpec.getTLen();

                if (tLen >= 96 && tLen <= 128 && tLen % 8 == 0) {
                    this.tag = new byte[tLen / 8];
                } else {
                    throw new InvalidAlgorithmParameterException("GCM tag length must be {128, 120, 112, 104, 96}");
                }
                return iv;
            }
            if (params == null) {
                if (encrypt) {
                    this.tag = new byte[DEFAULT_TAG_LEN_BYTES];
                    // Return null to request that OpenSSL generate the GCM IV internally.
                    return null;
                }
                throw new InvalidAlgorithmParameterException("GCM Parameters required for decryption");
            }
            throw new InvalidAlgorithmParameterException("Invalid GCM Parameters");
        }

        @Override
        Class<? extends AlgorithmParameterSpec> getParameterSpecClass() {
            return GCMParameterSpec.class;
        }

    }
}
