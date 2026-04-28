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

import java.security.PrivateKey;

import com.oracle.jipher.internal.openssl.Pkey;

/**
 * Abstract base class for private keys that are backed by an OpenSSL {@link Pkey}
 * instance.
 * <p>
 * It extends {@link JceOsslKey} to provide the common OpenSSL key handling and
 * implements {@link PrivateKey} so that it can be used with the standard JCA
 * {@code KeyFactory} APIs.
 * <p>
 * The key can be explicitly destroyed, which frees the native resources and
 * prevents any further use of the key material. Once destroyed, attempts to
 * access the key (e.g. via {@link #getPkey()} or {@link #getEncoded()}) will
 * result in an {@link IllegalStateException}.
 */
public abstract class JceOsslPrivateKey extends JceOsslKey implements PrivateKey {
    /**
     * Flag indicating whether {@link #destroy()} has been called.
     * When {@code true}, the underlying native {@link Pkey} has been freed and
     * the key must no longer be used.
     */
    private boolean destroyed;

    /**
     * Constructs a new {@code JceOsslPrivateKey}.
     *
     * @param alg   the algorithm name (e.g. {@code "RSA"}, {@code "EC"})
     * @param pkey  the native OpenSSL private key representation
     */
    JceOsslPrivateKey(String alg, Pkey pkey) {
        super(alg, pkey);
        this.destroyed = false;
    }

    /**
     * Destroys the key by freeing the native {@link Pkey} and marking the key
     * as destroyed. After this call, any operation that attempts to access the
     * key material will throw {@link IllegalStateException}.
     */
    @Override
    public void destroy() {
        this.pkey.free();
        this.destroyed = true;
    }

    /**
     * Returns {@code true} if {@link #destroy()} has been called.
     *
     * @return {@code true} if the key has been destroyed, {@code false} otherwise
     */
    @Override
    public boolean isDestroyed() {
        return this.destroyed;
    }

    /**
     * Retrieves the underlying OpenSSL {@link Pkey}.
     *
     * @return the native private key object
     * @throws IllegalStateException if the key has been destroyed
     */
    public Pkey getPkey() {
        if (isDestroyed()) {
            throw new IllegalStateException("Destroyed Key");
        }
        return super.getPkey();
    }

    /**
     * Returns the encoded form of the private key.
     *
     * @return the key encoding in its standard format (typically PKCS#8)
     * @throws IllegalStateException if the key has been destroyed. This guards
     *         against attempts to serialize a key whose native resources have
     *         already been freed.
     */
    @Override
    public byte[] getEncoded() {
        if (isDestroyed()) {
            // Note: This causes an attempt to serialize a destroyed JceOsslPrivateKey
            // to fail because JceOsslKey.writeReplace() calls getEncoded()
            throw new IllegalStateException("Destroyed Key");
        }
        return super.getEncoded();
    }
}
