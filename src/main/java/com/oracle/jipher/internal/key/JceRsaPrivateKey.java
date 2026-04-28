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
import java.security.interfaces.RSAPrivateCrtKey;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newNull;
import static com.oracle.jipher.internal.asn1.Asn1.newOctetString;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * {@link RSAPrivateCrtKey} implementation with an {@code EVP_PKEY} backed key.
 */
public final class JceRsaPrivateKey extends JceOsslPrivateKey implements RSAPrivateCrtKey {

    private static final String ALG = "RSA";

    private static final Asn1BerValue ID_RSA_ENCRYPTION = newOid("1.2.840.113549.1.1.1");

    public JceRsaPrivateKey(Pkey pkey) {
        super(ALG, pkey);
    }

    @Override
    public BigInteger getModulus() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaModulus();
    }

    @Override
    public BigInteger getPublicExponent() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPublicExponent();
    }

    @Override
    public BigInteger getPrivateExponent() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPrivateExponent();
    }

    @Override
    public BigInteger getPrimeP() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPrimeP();
    }

    @Override
    public BigInteger getPrimeQ() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPrimeQ();
    }

    @Override
    public BigInteger getPrimeExponentP() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPrimeExponentP();
    }

    @Override
    public BigInteger getPrimeExponentQ() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaPrimeExponentQ();
    }

    @Override
    public BigInteger getCrtCoefficient() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getRsaCrtCoefficient();
    }

    /**
     * Encode the RSA private key into PKCS #8 PrivateKeyInfo DER format.
     *
     * @return The DER-encoded private key bytes
     */
    @Override
    byte[] derEncode() throws InvalidKeyException {
        byte[][] params = null;
        try {
            params = this.pkey.getRsaPrivateKeyData();

            // PrivateKeyInfo
            Asn1BerValue rsaPrivKey = newSequence(
                    // version Version
                    newInteger(0),
                    // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
                    newSequence(
                            ID_RSA_ENCRYPTION,  // algorithm OBJECT IDENTIFIER
                            newNull()           // parameters ANY OPTIONAL
                    ),

                    // privateKey OCTET STRING
                    newOctetString(
                            // RSAPrivateKey
                            newSequence(
                                    newInteger(0),          // version Version
                                    newInteger(params[0]),  // modulus INTEGER
                                    newInteger(params[1]),  // publicExponent INTEGER
                                    newInteger(params[2]),  // privateExponent INTEGER
                                    newInteger(params[3]),  // prime1 INTEGER
                                    newInteger(params[4]),  // prime2 INTEGER
                                    newInteger(params[5]),  // exponent1 INTEGER
                                    newInteger(params[6]),  // exponent2 INTEGER
                                    newInteger(params[7])   // coefficient INTEGER
                            ).encodeDer()
                    )
            );
            return rsaPrivKey.encodeDerOctets();
        } finally {
            Util.clearArrays(params);
        }
    }
}
