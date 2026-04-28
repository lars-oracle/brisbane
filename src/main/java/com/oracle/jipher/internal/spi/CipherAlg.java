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

import java.security.InvalidKeyException;

/**
 * Encapsulates info about a symmetric cipher algorithm.
 * <p>
 * Supported OpenSSL algorithms are:
 * <pre>
 *     "aes-128-ecb","aes-192-ecb","aes-256-ecb",
 *     "aes-128-cbc","aes-192-cbc","aes-256-cbc",
 *     "aes-128-gcm","aes-192-gcm","aes-256-gcm",
 *     "aes-128-ctr","aes-192-ctr","aes-256-ctr",
 *     "aes-128-ofb","aes-192-ofb","aes-256-ofb",
 *     "aes-128-cfb","aes-192-cfb","aes-256-cfb",
 *     "des-ede3-cbc", "des-ede3-ecb",
 *     "id-aes128-wrap","id-aes192-wrap","id-aes256-wrap",
 *     "id-aes128-wrap-pad","id-aes192-wrap-pad","id-aes256-wrap-pad",
 *  </pre>
 */
abstract class CipherAlg {

    abstract String getName();

    abstract int getBlockSize();

    abstract boolean isValidKeySize(int keySize);

    void validateKeySize(int keySize) throws InvalidKeyException {
        if (!isValidKeySize(keySize)) {
            throw new InvalidKeyException("Invalid key length.");
        }
    }

    abstract String getAlg(int keySize, CipherMode mode);

    abstract boolean supportsMode(CipherMode mode);

    abstract boolean supportsPadding(CipherMode mode, CipherPadding padding);

    interface FixedModePad {
        CipherMode getMode();
        CipherPadding getPadding();
    }

    static abstract class AesAbstract extends CipherAlg {
        static final int BLOCK_SIZE = 16;

        @Override
        public String getName() {
            return "AES";
        }

        @Override
        public int getBlockSize() {
            return BLOCK_SIZE;
        }

        @Override
        public String getAlg(int keySize, CipherMode mode) {
            return "aes-" + keySize + "-" + mode.toString().toLowerCase();
        }

        @Override
        boolean isValidKeySize(int keyBytes) {
            return keyBytes == 16 || keyBytes == 24 || keyBytes == 32;
        }

    }

    static class AesFixed extends AesAbstract implements FixedModePad {
        private final int keySizeBits;
        private final CipherMode mode;
        private final CipherPadding pad;
        AesFixed(int keySize, CipherMode mode, CipherPadding pad) {
            this.keySizeBits = keySize;
            this.mode = mode;
            this.pad = pad;
        }

        public CipherMode getMode() {
            return this.mode;
        }

        public CipherPadding getPadding() {
            return this.pad;
        }

        @Override
        public boolean isValidKeySize(int keySize) {
            return keySizeBits == keySize * 8;
        }

        @Override
        public boolean supportsMode(CipherMode m) {
            return this.mode == m;
        }

        @Override
        public boolean supportsPadding(CipherMode m, CipherPadding padding) {
            return this.mode == m && this.pad == padding;
        }
    }

    static class AES extends AesAbstract {

        @Override
        public boolean supportsMode(CipherMode mode) {
            return switch (mode) {
                case CBC, ECB, CTR, CFB, OFB -> true;
                default -> false;
            };
        }

        @Override
        public boolean supportsPadding(CipherMode mode, CipherPadding padding) {
            if (padding == CipherPadding.PKCS5PADDING) {
                return mode == CipherMode.CBC || mode == CipherMode.ECB;
            }
            return true;
        }
    }

    static class AesGcm extends AesAbstract {

        int fixedKeySize = -1;
        AesGcm() {
            // Nothing to do.
        }
        AesGcm(int sizeBytes) {
            this.fixedKeySize = sizeBytes;
        }

        @Override
        public boolean isValidKeySize(int keySizeBytes) {
            if (this.fixedKeySize != -1) {
                return this.fixedKeySize == keySizeBytes;
            } else {
                return super.isValidKeySize(keySizeBytes);
            }
        }

        @Override
        public boolean supportsMode(CipherMode mode) {
            return mode == CipherMode.GCM;
        }

        @Override
        public boolean supportsPadding(CipherMode mode, CipherPadding padding) {
            return padding == CipherPadding.NOPADDING;
        }
    }

    static abstract class DesEdeAbstract extends CipherAlg {
        static final int BLOCK_SIZE = 8;

        @Override
        public String getName() {
            return "DESede";
        }

        @Override
        public int getBlockSize() {
            return BLOCK_SIZE;
        }

        @Override
        public boolean isValidKeySize(int keySize) {
            return keySize == 24;
        }

        @Override
        public String getAlg(int keySize, CipherMode mode) {
            return "des-ede3-" + mode.toString().toLowerCase();
        }
    }

    static class DesEdeFixed extends DesEdeAbstract implements FixedModePad {
        private final CipherMode mode;
        private final CipherPadding pad;
        DesEdeFixed(CipherMode mode, CipherPadding pad) {
            this.mode = mode;
            this.pad = pad;
        }

        public CipherMode getMode() {
            return this.mode;
        }

        public CipherPadding getPadding() {
            return this.pad;
        }

        @Override
        public boolean supportsMode(CipherMode m) {
            return this.mode == m;
        }

        @Override
        public boolean supportsPadding(CipherMode m, CipherPadding padding) {
            return this.mode == m && this.pad == padding;
        }
    }

    static class DesEde extends DesEdeAbstract {

        @Override
        public boolean supportsMode(CipherMode mode) {
            return switch (mode) {
                case CBC, ECB -> true;
                default -> false;
            };
        }

        @Override
        public boolean supportsPadding(CipherMode mode, CipherPadding padding) {
            if (padding == CipherPadding.PKCS5PADDING) {
                return mode == CipherMode.CBC || mode == CipherMode.ECB;
            }
            return true;
        }
    }

    static class AesKeyWrap extends AesAbstract {
        int fixedKeyBits = -1;

        AesKeyWrap() {
            // Nothing
        }
        AesKeyWrap(int size) {
            this.fixedKeyBits = size;
        }

        @Override
        public boolean isValidKeySize(int keyBytes) {
            if (this.fixedKeyBits == -1) {
                return super.isValidKeySize(keyBytes);
            } else {
                return keyBytes * 8 == this.fixedKeyBits;
            }
        }

        @Override
        boolean supportsMode(CipherMode mode) {
            return false;
        }
        @Override
        boolean supportsPadding(CipherMode mode, CipherPadding padding) {
            return false;
        }

        @Override
        public String getAlg(int keyBits, CipherMode mode) {
            if (mode == CipherMode.KW) {
                return "id-aes" + keyBits + "-wrap";
            } else {
                return "id-aes" + keyBits + "-wrap-pad";
            }
        }
    }



}
