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

import java.io.Serial;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.KeyRep;
import java.security.PrivateKey;
import java.security.ProviderException;
import java.security.PublicKey;

import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.openssl.Pkey;

/**
 * Abstract parent class for all asymmetric {@link Key}s backed by OpenSSL Pkey.
 */
public abstract class JceOsslKey implements Key {

    private final String alg;
    final Pkey pkey;

    JceOsslKey(String alg, Pkey pkey) {
        this.alg = alg;
        this.pkey = pkey;
    }

    abstract byte[] derEncode() throws InvalidKeyException;

    @Override
    public byte[] getEncoded() {
        try {
            return this.derEncode();
        } catch (InvalidKeyException e) {
            throw new ProviderException(e);
        }
    }

    @Override
    public String getFormat() {
        return (this instanceof PublicKey) ? "X.509" : "PKCS#8";
    }

    @Override
    public String getAlgorithm() {
        return this.alg;
    }

    public Pkey getPkey() {
        return pkey;
    }

    @Override
    public int hashCode() {
        byte[] der = this.getEncoded();
        try {
            return Util.hashCode(der);
        } finally {
            Util.clearArray(der);
        }
    }

    @Override
    public boolean equals(Object obj) {
        if (this == obj) {
            return true;
        } else if (!(obj instanceof Key)) {
            return false;
        } else {
            byte[] der = this.getEncoded();
            byte[] otherDer = null;
            try {
                otherDer = ((Key) obj).getEncoded();
                return Util.equalsCT(der, otherDer);
            } finally {
                Util.clearArray(der);
                Util.clearArray(otherDer);
            }
        }
    }

    @Serial
    protected Object writeReplace() {
        return new KeyRep(this instanceof PrivateKey ? KeyRep.Type.PRIVATE : KeyRep.Type.PUBLIC,
                this.getAlgorithm(), this.getFormat(), this.getEncoded());
    }
}
