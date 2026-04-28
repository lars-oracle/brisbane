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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.common.TripleDesUtil;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Symmetric cipher implementation of {@link SecretKeyFactorySpi}.
 */
public abstract class SymmKeyFactory extends SecretKeyFactorySpi {

    final CipherAlg alg;
    SymmKeyFactory(CipherAlg alg) {
        this.alg = alg;
    }

    abstract SecretKey createKey(byte[] key);

    KeySpec createKeySpec(byte[] key, Class<?> keySpec) throws InvalidKeySpecException {
        if (keySpec != null && keySpec.isAssignableFrom(SecretKeySpec.class)) {
            if (this.alg.isValidKeySize(key.length)) {
                return new SecretKeySpec(key, this.alg.getName());
            } else {
                throw new InvalidKeySpecException("Invalid key length");
            }
        } else {
            throw new InvalidKeySpecException("Expected KeySpec to be assignable from SecretKeySpec");
        }
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey secretKey, Class<?> keySpec) throws InvalidKeySpecException {
        if (secretKey.getAlgorithm().equalsIgnoreCase(this.alg.getName()) && secretKey.getFormat().equalsIgnoreCase("RAW")) {
            byte[] encoded = secretKey.getEncoded();
            try {
                return createKeySpec(encoded, keySpec);
            } finally {
                clearArray(encoded);
            }
        } else {
            throw new InvalidKeySpecException("Invalid key");
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof SecretKeySpec) {
            byte[] key = ((SecretKeySpec) keySpec).getEncoded();
            try {
                if (!alg.isValidKeySize(key.length)) {
                    throw new InvalidKeySpecException("Invalid key size for " + this.alg.getName());
                }
                return createKey(key);
            } finally {
                clearArray(key);
            }
        } else {
            throw new InvalidKeySpecException("KeySpec not acceptable for " + this.alg.getName());
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey secretKey) throws InvalidKeyException {
        byte[] key = secretKey.getEncoded();
        try {
            if (!alg.isValidKeySize(key.length)) {
                throw new InvalidKeyException("Invalid key size for " + this.alg.getName());
            }
            return createKey(key);
        } finally {
            clearArray(key);
        }
    }

    public static final class AES extends SymmKeyFactory {
        public AES() {
            super(new CipherAlg.AES());
        }

        @Override
        SecretKey createKey(byte[] key) {
            return new SecretKeySpec(key, this.alg.getName());
        }
    }

    public static final class DESede extends SymmKeyFactory {

        public DESede() {
            super(new CipherAlg.DesEde());
        }

        @Override
        SecretKey createKey(byte[] key) {
            TripleDesUtil.setParityBits(key);
            return new SecretKeySpec(key, this.alg.getName());
        }

        @Override
        protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
            if (keySpec instanceof DESedeKeySpec spec) {
                byte[] key = spec.getKey();
                try {
                    return createKey(key);
                } finally {
                    clearArray(key);
                }
            }
            return super.engineGenerateSecret(keySpec);
        }

        @Override
        KeySpec createKeySpec(byte[] key, Class<?> keySpec) throws InvalidKeySpecException {
            try {
                if (keySpec != null && keySpec.isAssignableFrom(DESedeKeySpec.class)) {
                    return new DESedeKeySpec(key);
                }
                return super.createKeySpec(key, keySpec);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException("Invalid key");
            }
        }
    }

}
