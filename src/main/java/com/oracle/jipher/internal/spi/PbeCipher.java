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
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;
import com.oracle.jipher.internal.openssl.Rand;

import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.common.Util.destroyKey;

/**
 * PBES2 Cipher implementations.
 */
public abstract class PbeCipher extends FeedbackCipher {

    private static final int DEFAULT_SALT_SIZE_BYTES = 20;
    private static final int DEFAULT_ITER_COUNT = 50000;

    private final String algorithm;
    final MdAlg digest;
    final int keySizeBits;

    PbeCipher(String algorithm, CipherAlg cipherAlg, MdAlg digest, int keySizeBits) throws NoSuchAlgorithmException, NoSuchPaddingException {
        super(cipherAlg);
        this.algorithm = algorithm;
        this.digest = digest;
        this.keySizeBits = keySizeBits;
    }

    @Override
    protected void engineInit(int cipherMode, Key key, AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidKeyException, InvalidAlgorithmParameterException {
        PBEParameterSpec pbeParamSpec;
        try {
            pbeParamSpec = (PBEParameterSpec) algorithmParameterSpec;
            if (pbeParamSpec == null && this.paramSpec != null) {
                pbeParamSpec = (PBEParameterSpec) this.paramSpec;
            }
        } catch (ClassCastException ex) {
            throw new InvalidAlgorithmParameterException("Invalid parameters, expected PBE parameters");
        }

        byte[] salt;
        int iter;

        AlgorithmParameterSpec innerAlgParamSpec;
        if (pbeParamSpec != null) {
            salt = pbeParamSpec.getSalt();
            if (salt.length < getMinSaltLen()) {
                throw new InvalidAlgorithmParameterException("Salt must be at least " + getMinSaltLen() + " bytes long");
            }
            iter = pbeParamSpec.getIterationCount();
            if (iter < 0) {
                throw new InvalidAlgorithmParameterException("IterationCount must be a positive number");
            }
            if (iter == 0) {
                iter = DEFAULT_ITER_COUNT;
            }
            if (iter < getMinIterCnt()) {
                throw new InvalidAlgorithmParameterException("IterationCount must be at least " + getMinIterCnt());
            }
            innerAlgParamSpec = pbeParamSpec.getParameterSpec();
        } else {
            if (cipherMode == Cipher.DECRYPT_MODE || cipherMode == Cipher.UNWRAP_MODE) {
                throw new InvalidAlgorithmParameterException("Parameters missing");
            }
            salt = Rand.generate(DEFAULT_SALT_SIZE_BYTES);
            iter = DEFAULT_ITER_COUNT;
            innerAlgParamSpec = null;
        }

        if (!(key instanceof SecretKey)) {
            throw new InvalidKeyException("Only SecretKey permitted");
        }
        byte[] pwBytes = getKeyEncoding((SecretKey) key);

        byte[] dk = null;
        SecretKey dKey = null;
        try {
            if (pwBytes.length < getMinPwdLen()) {
                throw new InvalidKeyException("Password based key encoding must provide at least " + getMinPwdLen() + " bytes");
            }
            dk = deriveKey(pwBytes, salt, iter);
            dKey = new SecretKeySpec(dk, this.cipherAlg.getName());
            innerAlgParamSpec = deriveIv(pwBytes, salt, iter, innerAlgParamSpec);
            pbeParamSpec = new PBEParameterSpec(salt, iter, innerAlgParamSpec);
            super.engineInit(cipherMode, dKey, pbeParamSpec, secureRandom);
        } finally {
            clearArray(pwBytes);
            clearArray(dk);
            destroyKey(dKey);
        }
    }

    abstract byte[] getKeyEncoding(SecretKey key);

    abstract AlgorithmParameterSpec deriveIv(byte[] pwBytes, byte[] salt, int iter, AlgorithmParameterSpec innerAlgParamSpec);

    abstract int getMinIterCnt();
    abstract int getMinSaltLen();
    abstract int getMinPwdLen();
    abstract byte[] deriveKey(byte[] pwBytes, byte[] salt, int iter) throws InvalidAlgorithmParameterException;

    @Override
    Class<? extends AlgorithmParameterSpec> getParameterSpecClass() {
        return PBEParameterSpec.class;
    }

    @Override
    String getAlgorithmParametersAlg() {
        return this.algorithm;
    }

    static abstract class Pbes2Cipher extends PbeCipher {
        Pbes2Cipher(String algorithm, MdAlg digest, int keySizeBits) throws NoSuchAlgorithmException, NoSuchPaddingException {
            super(algorithm, new CipherAlg.AesFixed(keySizeBits, CipherMode.CBC, CipherPadding.PKCS5PADDING), digest, keySizeBits);
        }

        @Override
        byte[] getKeyEncoding(SecretKey key) {
            return key.getEncoded();
        }

        @Override
        AlgorithmParameterSpec deriveIv(byte[] pwBytes, byte[] salt, int iter, AlgorithmParameterSpec innerAlgParamSpec) {
            return innerAlgParamSpec;
        }

        @Override
        int getMinIterCnt() {
            return 1000; // SP 800-132 Section 5.2 - A minimum iteration count of 1,000 is recommended
        }

        @Override
        int getMinSaltLen() {
            return 16; // SP 800-132 Section 5.1 - the salt shall be at least 128 bits
        }

        @Override
        int getMinPwdLen() {
            return ToolkitProperties.getJipherPbkdf2MinimumPasswordLengthValue();
        }

        @Override
        byte[] deriveKey(byte[] pwBytes, byte[] salt, int iter) throws InvalidAlgorithmParameterException {
            return Kdf.pbkdf2Derive(pwBytes, salt, iter, this.digest, this.keySizeBits / 8);
        }

        @Override
        AlgorithmParameterSpec getParamSpec(byte[] iv, AlgorithmParameterSpec spec) {
            PBEParameterSpec pbeParamSpec = (PBEParameterSpec) spec;
            return new PBEParameterSpec(pbeParamSpec.getSalt(), pbeParamSpec.getIterationCount(), new IvParameterSpec(iv));
        }

        @Override
        byte[] verifyParams(AlgorithmParameterSpec spec, boolean encrypt) throws InvalidAlgorithmParameterException {
            PBEParameterSpec pbeParamSpec = (PBEParameterSpec) spec;
            IvParameterSpec ivParamSpec = (IvParameterSpec) pbeParamSpec.getParameterSpec();
            return super.verifyParams(ivParamSpec, encrypt);
        }
    }

    public static final class PBEWithHmacSHA1AndAES128 extends Pbes2Cipher {
        public PBEWithHmacSHA1AndAES128() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA1AndAES_128", MdAlg.SHA1, 128);
        }
    }

    public static final class PBEWithHmacSHA224AndAES128 extends Pbes2Cipher {
        public PBEWithHmacSHA224AndAES128() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA224AndAES_128", MdAlg.SHA224, 128);
        }
    }

    public static final class PBEWithHmacSHA256AndAES128 extends Pbes2Cipher {
        public PBEWithHmacSHA256AndAES128() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA256AndAES_128", MdAlg.SHA256, 128);
        }
    }

    public static final class PBEWithHmacSHA384AndAES128 extends Pbes2Cipher {
        public PBEWithHmacSHA384AndAES128() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA384AndAES_128", MdAlg.SHA384, 128);
        }
    }

    public static final class PBEWithHmacSHA512AndAES128 extends Pbes2Cipher {
        public PBEWithHmacSHA512AndAES128() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA512AndAES_128", MdAlg.SHA512, 128);
        }
    }

    public static final class PBEWithHmacSHA1AndAES256 extends Pbes2Cipher {
        public PBEWithHmacSHA1AndAES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA1AndAES_256", MdAlg.SHA1, 256);
        }
    }

    public static final class PBEWithHmacSHA224AndAES256 extends Pbes2Cipher {
        public PBEWithHmacSHA224AndAES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA224AndAES_256", MdAlg.SHA224, 256);
        }
    }

    public static final class PBEWithHmacSHA256AndAES256 extends Pbes2Cipher {
        public PBEWithHmacSHA256AndAES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA256AndAES_256", MdAlg.SHA256, 256);
        }
    }

    public static final class PBEWithHmacSHA384AndAES256 extends Pbes2Cipher {
        public PBEWithHmacSHA384AndAES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA384AndAES_256", MdAlg.SHA384, 256);
        }
    }

    public static final class PBEWithHmacSHA512AndAES256 extends Pbes2Cipher {
        public PBEWithHmacSHA512AndAES256() throws NoSuchAlgorithmException, NoSuchPaddingException {
            super("PBEWithHmacSHA512AndAES_256", MdAlg.SHA512, 256);
        }
    }

}
