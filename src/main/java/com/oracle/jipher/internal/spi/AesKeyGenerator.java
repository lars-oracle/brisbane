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
 * Implementation of {@link KeyGeneratorSpi} that produces secret keys for
 * the AES algorithm.
 * <p>
 * The generator supports the standard AES key sizes of 128, 192 and 256 bits.
 * By default, it uses the key size defined by {@link KeySizeConfiguration}.
 * The class also provides three fixed-size inner subclasses -
 * {@link Aes128}, {@link Aes192} and {@link Aes256} - that enforce a specific
 * key length.
 */
public class AesKeyGenerator extends KeyGeneratorSpi {

    /** Default key size in bytes, obtained from {@link KeySizeConfiguration}. */
    private static final int DEFAULT_KEY_SIZE = KeySizeConfiguration.getAESKeySize() >>> 3;
    /** Current key size in bytes used for generation. */
    protected int keySize = DEFAULT_KEY_SIZE;

    /**
     * Initializes the key generator with the given key size (in bits).
     *
     * <p>{@code SecureRandom} argument is ignored because random data is obtained
     * from the native OpenSSL {@code RAND_bytes} implementation via {@link Rand#generate(int)}
     * when needed.
     *
     * @param keySize      the required size of the key in bits.
     * @param secureRandom a source of randomness (ignored)
     */
    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        if (keySize != 128 && keySize != 192 && keySize != 256) {
            throw new InvalidParameterException("Invalid key size, must be 128, 192 or 256.");
        }
        this.keySize = keySize >>> 3;
    }

    /**
     * Initializes the key generator with the default key size defined by
     * {@link KeySizeConfiguration}.
     *
     * <p>{@code SecureRandom} argument is ignored because random data is obtained
     * from the native OpenSSL {@code RAND_bytes} implementation via {@link Rand#generate(int)}
     * when needed.
     *
     * @param secureRandom a source of randomness (ignored)
     */
    @Override
    protected void engineInit(SecureRandom secureRandom) {
        this.keySize = DEFAULT_KEY_SIZE;
    }

    /**
     * AES key generation implementation does not accept any {@link AlgorithmParameterSpec}.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        throw new InvalidAlgorithmParameterException("AES key generation does not take any parameters");
    }

    /**
     * Generates a new AES secret key.
     *
     * @return a {@link SecretKey} of the configured size for the "AES" algorithm
     */
    @Override
    protected SecretKey engineGenerateKey() {
        byte[] bytes = Rand.generate(this.keySize);
        try {
            return new SecretKeySpec(bytes, "AES");
        } finally {
            clearArray(bytes);
        }
    }

    /**
     * Base class for fixed-size AES key generators. Subclasses set a constant
     * key size in bits and reject attempts to change it via {@code engineInit}.
     */
    static abstract class AesFixed extends AesKeyGenerator {
        /**
         * Constructs the generator with a predefined key size.
         *
         * @param keySizeBits the key size in bits (128, 192, or 256)
         */
        protected AesFixed(int keySizeBits) {
            this.keySize = keySizeBits >>> 3;
        }

        /**
         * Validates that the supplied key size matches the fixed size.
         *
         * @param keySize the key size in bits
         * @param secureRandom a source of randomness (ignored)
         * @throws InvalidParameterException if the size does not match the fixed size
         */
        @Override
        protected void engineInit(int keySize, SecureRandom secureRandom) {
            if (this.keySize != keySize >>> 3) {
                throw new InvalidParameterException("Incorrect key size");
            }
        }

        /** No-op initialization - the size is already fixed. */
        @Override
        protected void engineInit(SecureRandom secureRandom) {
        }
    }

    /** Fixed-size generator for 128-bit AES keys. */
    public static final class Aes128 extends AesFixed {
        public Aes128() {
            super(128);
        }
    }

    /** Fixed-size generator for 192-bit AES keys. */
    public static final class Aes192 extends AesFixed {
        public Aes192() {
            super(192);
        }
    }

    /** Fixed-size generator for 256-bit AES keys. */
    public static final class Aes256 extends AesFixed {
        public Aes256() {
            super(256);
        }
    }
}
