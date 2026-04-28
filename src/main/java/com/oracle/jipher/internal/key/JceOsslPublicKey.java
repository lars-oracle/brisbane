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

package com.oracle.jipher.internal.key;

import java.security.PublicKey;

import com.oracle.jipher.internal.openssl.Pkey;

/**
 * Abstract base class for public keys that are backed by an OpenSSL {@link Pkey}
 * instance.
 * <p>
 * It extends {@link JceOsslKey} to provide common OpenSSL key handling and
 * implements {@link PublicKey} so that it can be used with the standard JCA
 * {@code KeyFactory} APIs.
 * <p>
 * The class optionally stores a pre-computed encoding (e.g., X.509 SubjectPublicKeyInfo)
 * which, if present, is returned by {@link #getEncoded()}.
 */
public abstract class JceOsslPublicKey extends JceOsslKey implements PublicKey {
    private final byte[] encoding;

    /**
     * Constructs a new {@code JceOsslPublicKey}.
     *
     * @param alg the algorithm name (e.g., "RSA", "EC")
     * @param pkey the native OpenSSL public key representation
     * @param encoding optional encoded form of the key; may be {@code null}
     */
    JceOsslPublicKey(String alg, Pkey pkey, byte[] encoding) {
        super(alg, pkey);
        this.encoding = encoding;
    }

    /**
     * Returns the encoded form of the public key.
     * <p>
     * If an explicit {@code encoding} was supplied at construction time, a clone
     * of that byte array is returned to protect internal state. Otherwise, the
     * method delegates to {@link JceOsslKey#getEncoded()}.
     *
     * @return a cloned byte array containing the key encoding, or the superclass's
     *         encoding if none was provided
     */
    @Override
    public byte[] getEncoded() {
        if (this.encoding != null) {
            return this.encoding.clone();
        } else {
            return super.getEncoded();
        }
    }
}
