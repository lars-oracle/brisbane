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

import java.security.InvalidKeyException;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.openssl.EcCurve;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newBitString;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.common.EcUtil.encodePointUncompressed;

/**
 * {@link ECPublicKey} implementation with an {@code EVP_PKEY} backed key.
 */
public final class JceEcPublicKey extends JceOsslPublicKey implements ECPublicKey {

    private static final String ALG = "EC";

    private static final Asn1BerValue ID_EC_PUBLIC_KEY = newOid("1.2.840.10045.2.1");

    private final ECPoint point;
    private final ECParameterSpec params;

    public JceEcPublicKey(Pkey pkey, ECPoint point, ECParameterSpec params, byte[] encoding) {
        super(ALG, pkey, encoding);
        this.point = point;
        this.params = params;
    }

    public JceEcPublicKey(Pkey pkey, byte[] encoding) throws InvalidKeyException {
        super(ALG, pkey, encoding);
        this.point = this.pkey.getEcPublicKey();
        this.params = NamedCurves.lookup(this.pkey.getEcCurve());
    }

    @Override
    public ECParameterSpec getParams() {
        return this.params;
    }

    @Override
    public ECPoint getW() {
        return this.point;
    }

    /**
     * Encode the EC public key into X.509 SubjectPublicKeyInfo DER format.
     *
     * @return the DER-encoded X.509 SubjectPublicKeyInfo of the EC public
     * key.
     */
    @Override
    byte[] derEncode() throws InvalidKeyException {
        EcCurve curve = NamedCurves.lookup(this.params);
        if (curve == null) {
            throw new InvalidKeyException("Unsupported ECParameterSpec");
        }

        // SubjectPublicKeyInfo
        Asn1BerValue ecPubKey = newSequence(
                // algorithm AlgorithmIdentifier
                newSequence(
                        ID_EC_PUBLIC_KEY,   // algorithm OBJECT IDENTIFIER
                        newOid(curve.oid()) // parameters ANY OPTIONAL
                ),

                // subjectPublicKey BIT STRING
                newBitString(
                        // ECPoint
                        encodePointUncompressed(this.point, this.params)
                )
        );
        return ecPubKey.encodeDerOctets();
    }

    @Override
    public String toString() {
        return "EcPublicKey: curve=" + NamedCurves.lookup(this.params) +
                ",point.x=" + this.point.getAffineX() + ",point.y=" + this.point.getAffineY();
    }
}
