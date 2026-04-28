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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.openssl.EcCurve;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.explicit;
import static com.oracle.jipher.internal.asn1.Asn1.newExplicitTag;
import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newOctetString;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.common.EcUtil.encodePointUncompressed;
import static com.oracle.jipher.internal.common.Util.clearArrays;

/**
 * {@link ECPrivateKey} implementation with an {@code EVP_PKEY} backed key.
 */
public final class JceEcPrivateKey extends JceOsslPrivateKey implements ECPrivateKey {

    private static final String ALG = "EC";

    private static final Asn1BerValue ID_EC_PUBLIC_KEY = newOid("1.2.840.10045.2.1");

    private final ECPoint point; // May be null if not available
    private final ECParameterSpec params;

    public JceEcPrivateKey(Pkey pkey, ECPoint point, ECParameterSpec params) {
        super(ALG, pkey);
        this.point = point;
        this.params = params;
    }

    public JceEcPrivateKey(Pkey pkey) throws InvalidKeyException {
        super(ALG, pkey);
        this.point = this.pkey.getEcPublicKey();
        this.params = NamedCurves.lookup(this.pkey.getEcCurve());
    }

    @Override
    public ECParameterSpec getParams() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return params;
    }

    @Override
    public BigInteger getS() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getEcPrivateKeyAsBigInteger();
    }

    /**
     * Encode the EC private key into PKCS #8 PrivateKeyInfo DER format.
     *
     * @return the DER-encoded private key bytes
     */
    @Override
    byte[] derEncode() throws InvalidKeyException {
        EcCurve curve = NamedCurves.lookup(this.params);
        if (curve == null) {
            throw new InvalidKeyException("Unsupported ECParameterSpec");
        }
        Asn1BerValue curveOid = newOid(curve.oid());

        byte[] privateKeyBytes = this.pkey.getEcPrivateKeyAsByteArray();
        byte[] encodedPrivateKeyValue = encodePrivateValue(privateKeyBytes, this.params);
        try {
            // PrivateKeyInfo
            Asn1BerValue ecPrivKey = newSequence(
                    // version Version
                    newInteger(0),
                    // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
                    newSequence(
                            ID_EC_PUBLIC_KEY,   // algorithm OBJECT IDENTIFIER
                            curveOid            // parameters ANY OPTIONAL
                    ),
                    // privateKey PrivateKey
                    newOctetString(
                            // ECPrivateKey
                            newSequence(
                                    // version INTEGER
                                    newInteger(1),
                                    // privateKey OCTET STRING
                                    newOctetString(encodedPrivateKeyValue),

                                    // parameters [0] ECParameters {{ NamedCurve }} OPTIONAL
                                    // According to RFC 5915 section 3, "implementations that conform
                                    // to this document MUST always include the parameters field".
                                    newExplicitTag(0, curveOid),

                                    // publicKey [1] BIT STRING OPTIONAL
                                    // According to RFC 5915 section 3, "implementations that conform
                                    // to this document SHOULD always include the publicKey field".
                                    (this.point == null) ? null :
                                            explicit(1).newBitString(
                                                    // ECPoint
                                                    encodePointUncompressed(this.point, this.params)
                                            )
                            ).encodeDer()
                    )
            );
            return ecPrivKey.encodeDerOctets();
        } finally {
            clearArrays(privateKeyBytes, encodedPrivateKeyValue);
        }
    }

    private static byte[] encodePrivateValue(byte[] privBytes, ECParameterSpec params) {
        int pLen = (params.getOrder().bitLength() + 7) / 8;
        if (privBytes.length != pLen) {
            // Either truncate or pad with zero bytes on the left
            byte[] buf = new byte[pLen];
            int copyLen = Math.min(privBytes.length, pLen);
            System.arraycopy(privBytes, privBytes.length - copyLen, buf, pLen - copyLen, copyLen);
            privBytes = buf;
        }
        return privBytes;
    }
}
