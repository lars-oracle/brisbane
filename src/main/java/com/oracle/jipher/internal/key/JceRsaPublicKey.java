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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.interfaces.RSAPublicKey;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newBitString;
import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newNull;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * {@link RSAPublicKey} implementation with an {@code EVP_PKEY} backed key.
 */
public final class JceRsaPublicKey extends JceOsslPublicKey implements RSAPublicKey {

    private static final String ALG = "RSA";

    private static final Asn1BerValue ID_RSA_ENCRYPTION = newOid("1.2.840.113549.1.1.1");

    private final BigInteger mod;
    private final BigInteger e;

    public JceRsaPublicKey(Pkey pkey, BigInteger mod, BigInteger e, byte[] encoding) {
        super(ALG, pkey, encoding);
        this.mod = mod;
        this.e = e;
    }

    public JceRsaPublicKey(Pkey pkey, byte[] encoding) throws InvalidKeyException {
        super(ALG, pkey, encoding);
        this.mod = this.pkey.getRsaModulus();
        this.e = this.pkey.getRsaPublicExponent();
        if (this.mod == null || this.e == null) {
            throw new InvalidKeyException("Invalid RSA key value");
        }
    }

    @Override
    public BigInteger getModulus() {
        return this.mod;
    }

    @Override
    public BigInteger getPublicExponent() {
        return e;
    }

    /**
     * Encode the RSA public key into X.509 SubjectPublicKeyInfo DER format.
     *
     * @return the DER-encoded X.509 SubjectPublicKeyInfo of the RSA public
     * key.
     */
    @Override
    byte[] derEncode() {
        // SubjectPublicKeyInfo
        Asn1BerValue rsaPubKey = newSequence(
                // algorithm AlgorithmIdentifier
                newSequence(
                        ID_RSA_ENCRYPTION,  // algorithm OBJECT IDENTIFIER
                        newNull()           // parameters ANY OPTIONAL
                ),

                // subjectPublicKey BIT STRING
                newBitString(
                        // RSAPublicKey
                        newSequence(
                                newInteger(this.mod),   // modulus INTEGER
                                newInteger(this.e)      // publicExponent INTEGER
                        ).encodeDerOctets()
                )
        );
        return rsaPubKey.encodeDerOctets();
    }

    @Override
    public String toString() {
        return "RsaPublicKey: n=" + this.mod + ",e=" + this.e;
    }
}
