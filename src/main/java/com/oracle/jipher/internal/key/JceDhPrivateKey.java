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
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.common.Util;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.spi.DHFIPSParameterSpec;
import com.oracle.jipher.internal.spi.DHFIPSParameterValidationSpec;

import static com.oracle.jipher.internal.asn1.Asn1.newBitString;
import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newOctetString;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * {@link DHPrivateKey} implementation with an {@code EVP_PKEY} backed key.
 */
public final class JceDhPrivateKey extends JceOsslPrivateKey implements DHPrivateKey {

    private static final String ALG = "DH";

    private static final Asn1BerValue ID_DH_KEY_AGREEMENT = newOid("1.2.840.113549.1.3.1");
    private static final Asn1BerValue ID_DH_PUBLIC_NUMBER = newOid("1.2.840.10046.2.1");

    private final DHParameterSpec params;

    public JceDhPrivateKey(Pkey pkey, DHParameterSpec params) {
        super(ALG, pkey);
        this.params = params;
    }

    public JceDhPrivateKey(Pkey pkey) throws InvalidKeyException {
        super(ALG, pkey);
        this.params = this.pkey.getDhParams();
    }

    @Override
    public BigInteger getX() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.pkey.getDhPrivateKeyAsBigInteger();
    }

    @Override
    public DHParameterSpec getParams() {
        if (isDestroyed()) {
            throw new IllegalStateException("Key has been destroyed");
        }
        return this.params;
    }

    /**
     * Encodes the DH private key in PKCS #8 Private-Key Information Syntax -
     * see <a href="https://www.rfc-editor.org/rfc/rfc5208.html#section-5">RFC 5208 section 5</a>.
     * PrivateKeyAlgorithmIdentifier is defined as AlgorithmIdentifier in CCITT recommendation X.509.
     *
     * <p>The privateKeyAlgorithm algorithm ID can be either:
     * <pre>
     * iso(1) member-body(2) us(840) ansi-x942(10046) number-types(2) dhpublicnumber(1)
     * </pre>
     * if Q is known, in which case the AlgorithmIdentifier parameters are:
     * <pre>
     * DomainParameters ::= SEQUENCE {
     *     p       INTEGER, -- odd prime, p=jq +1
     *     g       INTEGER, -- generator, g
     *     q       INTEGER, -- factor of p-1
     *     j       INTEGER OPTIONAL, -- subgroup factor validationParms  ValidationParms OPTIONAL }
     * </pre>
     * as defined in <a href="https://www.rfc-editor.org/rfc/rfc3279.html#section-2.3.3">RFC 3279 section-2.3.3</a>
     *
     * <p>OR
     * <pre>
     * {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-3(3) dhKeyAgreement(1)}
     * </pre>
     * if Q is unknown, in which case the AlgorithmIdentifier parameters are:
     * <pre>
     * DHParameter ::= SEQUENCE {
     *     prime INTEGER, -- p
     *     base INTEGER, -- g
     *     privateValueLength INTEGER OPTIONAL }
     * </pre>
     * as defined in PKCS #3 section 9.
     */
    @Override
    byte[] derEncode() {
        byte[] privateKeyBytes = null;
        try {
            privateKeyBytes = this.pkey.getDhPrivateKeyAsByteArray();
            Asn1BerValue dhPrivKey;
            if (this.params instanceof DHFIPSParameterSpec dhFipsParams) {
                DHFIPSParameterValidationSpec validation = dhFipsParams.getParameterValidationSpec();

                // PrivateKeyInfo
                dhPrivKey = newSequence(
                        // version Version
                        newInteger(0),
                        // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
                        newSequence(
                                // algorithm OBJECT IDENTIFIER
                                ID_DH_PUBLIC_NUMBER,
                                // parameters ANY OPTIONAL
                                newSequence(
                                        newInteger(dhFipsParams.getP()),
                                        newInteger(dhFipsParams.getG()),
                                        newInteger(dhFipsParams.getQ()),
                                        (dhFipsParams.getJ() != null) ? newInteger(dhFipsParams.getJ()) : null,
                                        (validation != null) ?
                                                newSequence(
                                                        newBitString(validation.seed()),
                                                        newInteger(validation.pgenCounter())
                                                ) : null
                                )
                        ),
                        // privateKey PrivateKey
                        newOctetString(
                                // DHPrivateKey ::= INTEGER -- private key, X
                                newInteger(privateKeyBytes).encodeDer()
                        )
                );
            } else {
                // PrivateKeyInfo
                dhPrivKey = newSequence(
                        // version Version
                        newInteger(0),
                        // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
                        newSequence(
                                // algorithm OBJECT IDENTIFIER
                                ID_DH_KEY_AGREEMENT,
                                // parameters ANY OPTIONAL
                                newSequence(
                                        // prime INTEGER, -- p
                                        newInteger(this.params.getP()),
                                        // base INTEGER, -- g
                                        newInteger(this.params.getG()),
                                        // privateValueLength INTEGER OPTIONAL
                                        (this.params.getL() != 0) ? newInteger(this.params.getL()) : null
                                )
                        ),
                        // privateKey PrivateKey
                        newOctetString(
                                // DHPrivateKey ::= INTEGER -- private key, X
                                newInteger(privateKeyBytes).encodeDer()
                        )
                );
            }
            return dhPrivKey.encodeDerOctets();
        } finally {
            Util.clearArray(privateKeyBytes);
        }
    }
}
