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

import java.io.IOException;
import java.io.ObjectOutputStream;
import java.io.Serial;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Destroyable;

import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.common.Util.utf8Encode;
import static com.oracle.jipher.internal.fips.CryptoOp.KEYGEN;

/**
 * PBKDF2 {@link SecretKeyFactorySpi} implementation.
 */
public abstract class Pbkdf2KeyFactory extends SecretKeyFactorySpi {

    private final String algorithm;
    private final MdAlg digest;

    Pbkdf2KeyFactory(String algorithm, MdAlg digest) {
        this.algorithm = algorithm;
        this.digest = digest;
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (!(key instanceof PBEKey)) {
            throw new InvalidKeySpecException("Invalid key format/algorithm");
        }
        if (keySpec == null || !keySpec.isAssignableFrom(PBEKeySpec.class)) {
            throw new InvalidKeySpecException("Expected KeySpec class to be assignable from PBEKeySpec");
        }
        return toKeySpec((PBEKey)key);
    }

    private PBEKeySpec toKeySpec(PBEKey pbeKey) {
        byte[] dk = pbeKey.getEncoded();
        Arrays.fill(dk, (byte)0);
        int keyLength = dk.length * 8;

        char[] password = pbeKey.getPassword();
        try {
            return new PBEKeySpec(password, pbeKey.getSalt(),
                pbeKey.getIterationCount(), keyLength);
        } finally {
            clearArray(password);
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("Invalid key spec");
        }
        return generateSecret((PBEKeySpec)keySpec);
    }

    byte[] encodePassword(char[] password) {
        return utf8Encode(password);
    }

    private PBEKeyImpl generateSecret(PBEKeySpec keySpec) throws InvalidKeySpecException {
        byte[] salt = keySpec.getSalt();
        if (salt == null) {
            throw new InvalidKeySpecException("Salt not found");
        }
        // SP 800-132 Section 5.1 - the salt shall be at least 128 bits
        if (salt.length < 16) {
            throw new InvalidKeySpecException("Salt must be at least 16 bytes");
        }
        // SP 800-132 Section 5.2 - A minimum iteration count of 1,000 is recommended
        if (keySpec.getIterationCount() < 1000) {
            throw new InvalidKeySpecException("IterationCount must be at least 1000");
        }
        if (keySpec.getKeyLength() <= 0) {
            throw new InvalidKeySpecException("Key length not found");
        }
        try {
            Fips.enforcement().checkStrength(KEYGEN, "KDF", keySpec.getKeyLength());
        } catch (FIPSPolicyException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        }

        char[] password = keySpec.getPassword();
        byte[] pwBytes = null;
        try {
            pwBytes = encodePassword(password);

            int minPwdLen = ToolkitProperties.getJipherPbkdf2MinimumPasswordLengthValue();
            if (pwBytes.length < minPwdLen) {
                throw new InvalidKeySpecException("Password encoding must provide at least " + minPwdLen + " bytes");
            }

            int iter = keySpec.getIterationCount();
            byte[] dk = Kdf.pbkdf2Derive(pwBytes, salt, iter, this.digest, keySpec.getKeyLength() / 8);
            PBEKeyImpl pbeKey = new PBEKeyImpl(this.algorithm, dk, password, salt, iter);
            // Give ownership of the password char array to the new PBEKeyImpl
            password = null;
            return pbeKey;
        } catch (InvalidAlgorithmParameterException ex) {
            throw new InvalidKeySpecException("Failed to derive key", ex);
        } finally {
            clearArray(password);
            clearArray(pwBytes);
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        if (!(key instanceof PBEKey)
                || !key.getAlgorithm().equalsIgnoreCase(this.algorithm)
                || !key.getFormat().equalsIgnoreCase("RAW")) {
            throw new InvalidKeyException("Invalid key format/algorithm");
        }
        PBEKeySpec keySpec = toKeySpec((PBEKey)key);
        try {
            return generateSecret(keySpec);
        } catch (InvalidKeySpecException ex) {
            throw new InvalidKeyException(ex.getMessage(), ex);
        } finally {
            keySpec.clearPassword();
        }
    }

    static class EncodePassword8BIT extends Pbkdf2KeyFactory {
        public EncodePassword8BIT(String algorithm, MdAlg digest) {
            super(algorithm, digest);
        }

        @Override
        final byte[] encodePassword(char[] password) {
            byte[] bytes = new byte[password.length];
            for (int i = 0; i < password.length; ++i) {
                bytes[i] = (byte)password[i];
            }
            return bytes;
        }
    }

    public static final class SHA1 extends Pbkdf2KeyFactory {
        public SHA1() {
            super("PBKDF2WithHmacSHA1", MdAlg.SHA1);
        }
    }

    public static final class SHA224 extends Pbkdf2KeyFactory {
        public SHA224() {
            super("PBKDF2WithHmacSHA224", MdAlg.SHA224);
        }
    }

    public static final class SHA256 extends Pbkdf2KeyFactory {
        public SHA256() {
            super("PBKDF2WithHmacSHA256", MdAlg.SHA256);
        }
    }

    public static final class SHA384 extends Pbkdf2KeyFactory {
        public SHA384() {
            super("PBKDF2WithHmacSHA384", MdAlg.SHA384);
        }
    }

    public static final class SHA512 extends Pbkdf2KeyFactory {
        public SHA512() {
            super("PBKDF2WithHmacSHA512", MdAlg.SHA512);
        }
    }

    public static final class SHA1_8BIT extends EncodePassword8BIT {
        public SHA1_8BIT() {
            super("PBKDF2WithHmacSHA1and8BIT", MdAlg.SHA1);
        }
    }

    public static final class SHA224_8BIT extends EncodePassword8BIT {
        public SHA224_8BIT() {
            super("PBKDF2WithHmacSHA224and8BIT", MdAlg.SHA224);
        }
    }

    public static final class SHA256_8BIT extends EncodePassword8BIT {
        public SHA256_8BIT() {
            super("PBKDF2WithHmacSHA256and8BIT", MdAlg.SHA256);
        }
    }

    public static final class SHA384_8BIT extends EncodePassword8BIT {
        public SHA384_8BIT() {
            super("PBKDF2WithHmacSHA384and8BIT", MdAlg.SHA384);
        }
    }

    public static final class SHA512_8BIT extends EncodePassword8BIT {
        public SHA512_8BIT() {
            super("PBKDF2WithHmacSHA512and8BIT", MdAlg.SHA512);
        }
    }

    static final class PBEKeyImpl implements PBEKey, Destroyable {

        @Serial
        private static final long serialVersionUID = 3226143859873846573L;

        private final String algorithm;
        private byte[] dk;
        private char[] password;
        private final byte[] salt;
        private final int iterationCount;

        PBEKeyImpl(String algorithm, byte[] dk, char[] password, byte[] salt, int iterationCount) {
            this.algorithm = algorithm;
            this.dk = dk;
            this.password = password;
            this.salt = salt;
            this.iterationCount = iterationCount;
        }

        @Override
        public String getAlgorithm() {
            return this.algorithm;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }

        @Override
        public byte[] getEncoded() {
            if (this.dk == null) {
                throw new IllegalStateException("key data has been cleared");
            }
            return this.dk.clone();
        }

        @Override
        public char[] getPassword() {
            if (this.password == null) {
                throw new IllegalStateException("password has been cleared");
            }
            return this.password.clone();
        }

        @Override
        public byte[] getSalt() {
            return this.salt.clone();
        }

        @Override
        public int getIterationCount() {
            return this.iterationCount;
        }

        @Override
        public void destroy() {
            if (this.dk != null) {
                Arrays.fill(this.dk, (byte)0);
                this.dk = null;
            }
            if (this.password != null) {
                Arrays.fill(this.password, (char)0);
                this.password = null;
            }
        }

        @Override
        public boolean isDestroyed() {
            return this.dk == null && this.password == null;
        }

        @Override
        public int hashCode() {
            return this.algorithm.hashCode() + Util.hashCode(this.dk) +
                Util.hashCode(this.salt);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof PBEKeyImpl other) {
                return this.algorithm.equals(other.algorithm) &&
                        Util.equalsCT(this.dk, other.dk) &&
                        Util.equalsCT(this.password, other.password) &&
                        Util.equalsCT(this.salt, other.salt) &&
                        this.iterationCount == other.iterationCount;
            }
            return false;
        }

        // Prevent serialization of destroyed keys
        @Serial
        private void writeObject(ObjectOutputStream out) throws IOException {
            if (isDestroyed()) {
                throw new IllegalStateException("key destroyed");
            }
            out.defaultWriteObject();
        }
    }

}
