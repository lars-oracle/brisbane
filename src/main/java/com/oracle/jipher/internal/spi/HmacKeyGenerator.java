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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.openssl.Rand;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link KeyGeneratorSpi} for HMAC key generation.
 */
public abstract class HmacKeyGenerator extends KeyGeneratorSpi {

    private final int defaultKeyLenBytes;
    private final String algName;
    private int keyByteLen = -1;

    HmacKeyGenerator(String algName, int defaultKeyLen) {
        this.algName = algName;
        this.defaultKeyLenBytes = defaultKeyLen;
    }

    @Override
    protected void engineInit(int keyBits, SecureRandom secureRandom) {
        if (keyBits < 40) {
            throw new InvalidParameterException("Key length must be at least 40 bits.");
        }
        this.keyByteLen = (keyBits + 7)/8;
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.keyByteLen = this.defaultKeyLenBytes;
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("Hmac key generation does not take any parameters");
    }

    @Override
    protected SecretKey engineGenerateKey() {
        byte[] bytes = Rand.generate(this.keyByteLen == -1 ? this.defaultKeyLenBytes : this.keyByteLen);
        try {
            return new SecretKeySpec(bytes, this.algName);
        } finally {
            clearArray(bytes);
        }
    }

    /** HMAC-SHA1 key gen */
    public static class HmacSha1 extends HmacKeyGenerator {
        public HmacSha1() {
            super("HmacSHA1", 20);
        }
    }

    /** HMAC-SHA224 key gen */
    public static class HmacSha224 extends HmacKeyGenerator {
        public HmacSha224() {
            super("HmacSHA224", 28);
        }
    }

    /** HMAC-SHA256 key gen */
    public static class HmacSha256 extends HmacKeyGenerator {
        public HmacSha256() {
            super("HmacSHA256", 32);
        }
    }

    /** HMAC-SHA384 key gen */
    public static class HmacSha384 extends HmacKeyGenerator {
        public HmacSha384() {
            super("HmacSHA384", 48);
        }
    }

    /** HMAC-SHA512 key gen */
    public static class HmacSha512 extends HmacKeyGenerator {
        public HmacSha512() {
            super("HmacSHA512", 64);
        }
    }
}
