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
import java.security.InvalidKeyException;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Set;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactorySpi;
import javax.crypto.spec.PBEKeySpec;
import javax.security.auth.Destroyable;

import com.oracle.jipher.internal.common.Util;

import static com.oracle.jipher.internal.common.Util.asciiDecode;
import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.common.Util.utf8Decode;
import static com.oracle.jipher.internal.common.Util.utf8Encode;

/**
 * PBE {@link SecretKeyFactorySpi} implementation.
 */
public abstract class PbeKeyFactory extends SecretKeyFactorySpi {

    private static final Set<String> SUPPORTED_ALGS = new HashSet<>(
        Arrays.asList(
            "PBEWithHmacSHA1AndAES_128".toUpperCase(),
            "PBEWithHmacSHA224AndAES_128".toUpperCase(),
            "PBEWithHmacSHA256AndAES_128".toUpperCase(),
            "PBEWithHmacSHA384AndAES_128".toUpperCase(),
            "PBEWithHmacSHA512AndAES_128".toUpperCase(),
            "PBEWithHmacSHA1AndAES_256".toUpperCase(),
            "PBEWithHmacSHA224AndAES_256".toUpperCase(),
            "PBEWithHmacSHA256AndAES_256".toUpperCase(),
            "PBEWithHmacSHA384AndAES_256".toUpperCase(),
            "PBEWithHmacSHA512AndAES_256".toUpperCase()
        )
    );

    private final String algorithm;

    PbeKeyFactory(String algorithm) {
        this.algorithm = algorithm;
    }

    @Override
    protected KeySpec engineGetKeySpec(SecretKey key, Class<?> keySpec) throws InvalidKeySpecException {
        if (keySpec == null || !keySpec.isAssignableFrom(PBEKeySpec.class)) {
            throw new InvalidKeySpecException("Expected KeySpec class to be assignable from PBEKeySpec");
        }
        String keyAlg = key.getAlgorithm().toUpperCase();
        if (!SUPPORTED_ALGS.contains(keyAlg)
                || !key.getFormat().equalsIgnoreCase("RAW")) {
            throw new InvalidKeySpecException("Invalid key format/algorithm");
        }

        char[] password = decodePassword(key);
        try {
            return new PBEKeySpec(password);
        } finally {
            clearArray(password);
        }
    }

    @Override
    protected SecretKey engineGenerateSecret(KeySpec keySpec) throws InvalidKeySpecException {
        if (!(keySpec instanceof PBEKeySpec)) {
            throw new InvalidKeySpecException("Invalid key spec");
        }
        char[] password = ((PBEKeySpec)keySpec).getPassword();
        try {
            return new PasswordKey(this.algorithm, encodePassword(password));
        } finally {
            clearArray(password);
        }
    }

    @Override
    protected SecretKey engineTranslateKey(SecretKey key) throws InvalidKeyException {
        String keyAlg = key.getAlgorithm().toUpperCase();
        if (!SUPPORTED_ALGS.contains(keyAlg)
                || !key.getFormat().equalsIgnoreCase("RAW")) {
            throw new InvalidKeyException("Invalid key format/algorithm");
        }

        char[] password = decodePassword(key);
        try {
            return new PasswordKey(this.algorithm, encodePassword(password));
        } finally {
            clearArray(password);
        }
    }

    public static final class PBES2 extends PbeKeyFactory {
        public PBES2() {
            super("PBES2");
        }
    }

    public static final class PBEWithHmacSHA1AndAES128 extends PbeKeyFactory {
        public PBEWithHmacSHA1AndAES128() {
            super("PBEWithHmacSHA1AndAES_128");
        }
    }

    public static final class PBEWithHmacSHA224AndAES128 extends PbeKeyFactory {
        public PBEWithHmacSHA224AndAES128() {
            super("PBEWithHmacSHA224AndAES_128");
        }
    }

    public static final class PBEWithHmacSHA256AndAES128 extends PbeKeyFactory {
        public PBEWithHmacSHA256AndAES128() {
            super("PBEWithHmacSHA256AndAES_128");
        }
    }

    public static final class PBEWithHmacSHA384AndAES128 extends PbeKeyFactory {
        public PBEWithHmacSHA384AndAES128() {
            super("PBEWithHmacSHA384AndAES_128");
        }
    }

    public static final class PBEWithHmacSHA512AndAES128 extends PbeKeyFactory {
        public PBEWithHmacSHA512AndAES128() {
            super("PBEWithHmacSHA512AndAES_128");
        }
    }

    public static final class PBEWithHmacSHA1AndAES256 extends PbeKeyFactory {
        public PBEWithHmacSHA1AndAES256() {
            super("PBEWithHmacSHA1AndAES_256");
        }
    }

    public static final class PBEWithHmacSHA224AndAES256 extends PbeKeyFactory {
        public PBEWithHmacSHA224AndAES256() {
            super("PBEWithHmacSHA224AndAES_256");
        }
    }

    public static final class PBEWithHmacSHA256AndAES256 extends PbeKeyFactory {
        public PBEWithHmacSHA256AndAES256() {
            super("PBEWithHmacSHA256AndAES_256");
        }
    }

    public static final class PBEWithHmacSHA384AndAES256 extends PbeKeyFactory {
        public PBEWithHmacSHA384AndAES256() {
            super("PBEWithHmacSHA384AndAES_256");
        }
    }

    public static final class PBEWithHmacSHA512AndAES256 extends PbeKeyFactory {
        public PBEWithHmacSHA512AndAES256() {
            super("PBEWithHmacSHA512AndAES_256");
        }
    }

    public static final class PBE extends PbeKeyFactory {
        public PBE() {
            super("PBE");
        }
    }

    /*
     * The JDK providers only support ASCII passwords.  However, other crypto software such as OpenSSL supports
     * non-ASCII passwords.  For PKCS#5 PBE algorithms, OpenSSL encodes passwords using UTF-8. This follows the
     * interoperability recommendation from RFC-8018 section 3:
     *     "In the interest of interoperability, however, it is recommended that applications follow some common
     *     text encoding rules. ASCII and UTF-8 [RFC3629] are two possibilities."
     * As ASCII is a subset of UTF-8 this encoding choice is not incompatible with the JDK provider's implementation.
     */
    private static byte[] encodePassword(char[] password) {
        return utf8Encode(password);
    }

    // Interprets a SecretKey's RAW encoding as a password.
    private static char[] decodePassword(SecretKey key) {
        byte[] encoded = key.getEncoded();
        try {
            if (key instanceof PbeKeyFactory.PasswordKey) {
                // We know that key.getEncoded() UTF-8 encodes the password allowing
                // Jipher to support non-ASCII passwords.
                return utf8Decode(encoded);
            } else {
                // We must follow the JDK convention that the encoded SecretKey represents a 7-bit ASCII
                // encoding of the (ASCII) password characters where the high bit (bit 8) can be ignored.
                return asciiDecode(encoded);
            }
        } finally {
            clearArray(encoded);
        }
    }

    static final class PasswordKey implements SecretKey, Destroyable {

        @Serial
        private static final long serialVersionUID = -3658470171006990382L;

        final String algorithm;
        byte[] encoded;

        PasswordKey(String algorithm, byte[] encoded) {
            this.algorithm = algorithm;
            this.encoded = encoded;
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
            if (this.encoded == null) {
                throw new IllegalStateException("password has been cleared");
            }
            return this.encoded.clone();
        }

        @Override
        public void destroy() {
            if (this.encoded != null) {
                Arrays.fill(this.encoded, (byte)0);
                this.encoded = null;
            }
        }

        @Override
        public boolean isDestroyed() {
            return this.encoded == null;
        }

        @Override
        public int hashCode() {
            return this.algorithm.hashCode() + Arrays.hashCode(this.encoded);
        }

        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (obj instanceof PasswordKey other) {
                return this.algorithm.equals(other.algorithm) && Util.equalsCT(this.encoded, other.encoded);
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
