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

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.List;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.NamedCurves;
import com.oracle.jipher.internal.key.JceEcPrivateKey;
import com.oracle.jipher.internal.key.JceEcPublicKey;
import com.oracle.jipher.internal.openssl.EcCurve;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.common.InputChecks.isAllZeros;
import static com.oracle.jipher.internal.common.InputChecks.isNullOrZeroOrNegative;
import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link java.security.KeyFactorySpi} for EC keys.
 */
public final class EcKeyFactory extends AsymKeyFactory {

    private static final Asn1BerValue ID_EC_PUBLIC_KEY = newOid("1.2.840.10045.2.1");

    private static final int POINT_INFINITY = 0x00;
    private static final int UNCOMPRESSED = 0x04;

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof ECPrivateKeySpec ecPrivKeySpec) {
            if (isNullOrZeroOrNegative(ecPrivKeySpec.getS())) {
                throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
            }
            try {
                return generatePrivateInternal(ecPrivKeySpec.getS(), ecPrivKeySpec.getParams());
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePrivate(keySpec);
        }
    }

    PrivateKey generatePrivateInternal(BigInteger priv, ECParameterSpec params) throws InvalidKeyException {
        EcCurve curve = NamedCurves.lookup(params);
        if (curve == null) {
            throw new InvalidKeyException("Unsupported ECParameterSpec");
        }
        Pkey pkey = Pkey.newEcPriv(curve, priv);
        return new JceEcPrivateKey(pkey, null, params);
    }

    PrivateKey generatePrivateInternal(byte[] priv, ECPoint point, ECParameterSpec params) throws InvalidKeyException {
        EcCurve curve = NamedCurves.lookup(params);
        if (curve == null) {
            throw new InvalidKeyException("Unsupported ECParameterSpec");
        }
        Pkey pkey = Pkey.newEcPriv(curve, priv);
        return new JceEcPrivateKey(pkey, point, params);
    }

    @Override
    PrivateKey generatePrivateInternal(byte[] privDer) throws InvalidKeyException {
        byte[] privateBytes = null;
        try {
            Object[] ecParamSpecPublicPointAndPrivateKeyBytes = ecPrivDerDecode(privDer);
            ECParameterSpec parmSpec = (ECParameterSpec) ecParamSpecPublicPointAndPrivateKeyBytes[0];
            ECPoint publicPoint = (ECPoint) ecParamSpecPublicPointAndPrivateKeyBytes[1];
            privateBytes = (byte[]) ecParamSpecPublicPointAndPrivateKeyBytes[2];
            // RFC-5915 section 3 defines privateKey to be an UNSIGNED integer of ceiling (log2(n)/8) octets
            // (where n is the order of the curve)
            if (isAllZeros(privateBytes)) {
                throw new InvalidKeyException("Private key must not be zero");
            }
            return generatePrivateInternal(privateBytes, publicPoint, parmSpec);
        } finally {
            clearArray(privateBytes);
        }
    }

    /**
     * Decode the DER-encoded EC private key into parameters - (potentially null) public key point and private key value
     *
     * @param privDer the DER-encoded EC private key data
     * @return a 3 element array of Objects containing:
     * <ul>
     *     <li> the parameters as an ECParameterSpec,</li>
     *     <li> the public key as an ECPoint if present or null if absent, and</li>
     *     <li> the private key value as a byte[] containing a 2's-complement Integer in big-endian byte-order:
     *           the most significant byte is in the zeroth element.</li>
     * </ul>
     */
    private static Object[] ecPrivDerDecode(byte[] privDer) throws InvalidKeyException {
        try {
            // PrivateKeyInfo
            Asn1BerValue ecPrivKey = Asn1.decodeOne(privDer).count(3).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> ecPrivKeyValues = ecPrivKey.sequence();

            // version Version
            BigInteger privKeyInfoVer = ecPrivKeyValues.get(0).getInteger();
            if (!privKeyInfoVer.equals(BigInteger.ZERO)) {
                throw new Asn1DecodeException("Invalid PrivateKeyInfo version; was: " + privKeyInfoVer + ", expected: 0");
            }

            // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
            List<Asn1BerValue> algId = ecPrivKeyValues.get(1).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (!algorithm.equals(ID_EC_PUBLIC_KEY)) {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() + ", expected: " + ID_EC_PUBLIC_KEY.getOid());
            }
            // parameters ANY OPTIONAL
            String curveOid = algId.get(1).getOid();
            ECParameterSpec params = NamedCurves.lookup(curveOid);
            if (params == null) {
                throw new InvalidKeyException("Unsupported EC curve: " + curveOid);
            }

            // privateKey PrivateKey
            // ECPrivateKey
            Asn1BerValue ecPrivateKey = Asn1.decodeOne(ecPrivKeyValues.get(2).getOctetString()).count(2, 4);
            List<Asn1BerValue> keyValues = ecPrivateKey.sequence();

            // version INTEGER
            BigInteger ecPrivKeyVer = keyValues.get(0).getInteger();
            if (!ecPrivKeyVer.equals(BigInteger.ONE)) {
                throw new InvalidKeyException("Invalid ECPrivateKey version; was: " + ecPrivKeyVer + ", expected: 1");
            }

            byte[] privateKey = null;
            ECPoint point = null;
            try {
                // privateKey OCTET STRING
                privateKey = decodePrivateValue(keyValues.get(1), params);
                int index = 2;

                // parameters [0] ECParameters {{ NamedCurve }} OPTIONAL
                if (index < keyValues.size() && keyValues.get(index).hasTag(0)) {
                    // Verify that the curve OID matches the PKCS #8 curve OID
                    String innerCurveOid = keyValues.get(index++).tag(0).explicit().getOid();
                    if (!innerCurveOid.equals(curveOid)) {
                        throw new InvalidKeyException("ECPrivateKey curve OID " + innerCurveOid +
                                " doesn't match PKCS #8 curve OID " + curveOid);
                    }
                }

                // publicKey [1] BIT STRING OPTIONAL
                if (index < keyValues.size() && keyValues.get(index).hasTag(1)) {
                    // Keep the public key point for later encoding use.
                    byte[] encodedPoint = keyValues.get(index++).tag(1).explicit().getBitStringOctets();
                    point = decodePoint(encodedPoint, params);
                }

                if (index != keyValues.size()) {
                    throw new InvalidKeyException("Invalid ECPrivateKey encoding; unsupported elements");
                }
            } catch (Exception e) {
                clearArray(privateKey);
                throw e;
            }
            return new Object[] {
                    params,
                    point,
                    privateKey
            };
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode EC Private Key", ex);
        }
    }

    private static byte[] decodePrivateValue(Asn1BerValue value, ECParameterSpec params) throws InvalidKeyException {
        int expectedLength = (params.getOrder().bitLength() + 7) / 8;

        byte[] octetString = value.getOctetString();
        int actualLength = octetString.length;

        // RFC 5915 section 3 states: The PrivateKey "is an octet string of length ceiling (log2(n)/8)
        // (where n is the order of the curve) obtained from the UNSIGNED integer."
        // However, some encoders do not comply with the standard. They do not prefix zero-bytes
        // to ensure that the octet string is of length ceiling (log2(n)/8).  Hence, the following
        // test uses the more permissive comparator '>' in place of the RFC specified comparator '!='
        if (actualLength > expectedLength) {
            clearArray(octetString);
            throw new InvalidKeyException("Invalid ECPrivateKey encoding; unexpected length: " + actualLength);
        }

        // The octet string encodes an UNSIGNED integer.  Covert to a 2's-complement (signed) Integer:
        // If the most significant bit of the most significant byte is set then prefix a 0-byte.
        if ((octetString[0] & (byte) 0x80) != 0) {
            byte[] privateKey = new byte[octetString.length + 1];
            System.arraycopy(octetString, 0, privateKey, 1, octetString.length);
            clearArray(octetString);
            return privateKey;
        } else {
            return octetString;
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof ECPublicKeySpec ecPubKeySpec) {
            try {
                return generatePublicInternal(ecPubKeySpec.getW(), ecPubKeySpec.getParams(), null);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePublic(keySpec);
        }
    }

    PublicKey generatePublicInternal(ECPoint point, ECParameterSpec params, byte[] pubDer) throws InvalidKeyException {
        EcCurve curve = NamedCurves.lookup(params);
        if (curve == null) {
            throw new InvalidKeyException("Unsupported ECParameterSpec");
        }
        Pkey pkey = Pkey.newEcPub(curve, point, params);
        return new JceEcPublicKey(pkey, point, params, pubDer);
    }

    @Override
    PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException {
        ECPublicKeySpec ecPubKeySpec = ecPubDerDecode(pubDer);
        return generatePublicInternal(ecPubKeySpec.getW(), ecPubKeySpec.getParams(), pubDer);
    }

    /**
     * Decode the DER-encoded EC public key into an {@link ECPublicKeySpec}.
     *
     * @param pubDer the DER-encoded EC public key data
     * @return the  {@link ECPublicKeySpec}
     */
    private static ECPublicKeySpec ecPubDerDecode(byte[] pubDer) throws InvalidKeyException {
        try {
            // SubjectPublicKeyInfo
            Asn1BerValue ecPubKey = Asn1.decodeOne(pubDer).count(2).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> ecPubKeyValues = ecPubKey.sequence();

            // AlgorithmIdentifier
            List<Asn1BerValue> algId = ecPubKeyValues.get(0).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (!algorithm.equals(ID_EC_PUBLIC_KEY)) {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() + ", expected: " + ID_EC_PUBLIC_KEY.getOid());
            }
            // parameters ANY OPTIONAL
            String curveOid = algId.get(1).getOid();
            ECParameterSpec params = NamedCurves.lookup(curveOid);
            if (params == null) {
                throw new InvalidKeyException("Unsupported EC curve: " + curveOid);
            }

            // subjectPublicKey BIT STRING
            // ECPoint
            byte[] encodedPoint = ecPubKeyValues.get(1).getBitStringOctets();
            return new ECPublicKeySpec(decodePoint(encodedPoint, params), params);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode EC Public Key", ex);
        }
    }

    /**
     * Decode an EC point conforming to
     * <a href="https://www.secg.org/sec1-v2.pdf">SEC 1 Ver. 2.0</a> section 2.3.4.
     * Only uncompressed points are supported.
     *
     * @param encodedPoint the encoded point data
     * @param params       the ECParameterSpec
     * @return the {@link ECPoint}
     * @throws InvalidKeyException if the input data does not conform to
     *     <a href="https://www.secg.org/sec1-v2.pdf">SEC 1 Ver. 2.0</a> section 2.3.4.
     */
    private static ECPoint decodePoint(byte[] encodedPoint, ECParameterSpec params) throws InvalidKeyException {
        // ceil(log2(q)/8) where q is the order of the field
        int fLen = (params.getCurve().getField().getFieldSize() + 7) / 8;
        if (encodedPoint.length == 1 && encodedPoint[0] == POINT_INFINITY) {
            return ECPoint.POINT_INFINITY;
        } else if (encodedPoint.length == 1 + fLen) {
            throw new InvalidKeyException("Compressed EC Point format is not supported");
        } else if (encodedPoint.length == 1 + 2 * fLen && encodedPoint[0] == UNCOMPRESSED) {
            byte[] x = Arrays.copyOfRange(encodedPoint, 1, 1 + fLen);
            byte[] y = Arrays.copyOfRange(encodedPoint, 1 + fLen, encodedPoint.length);
            return new ECPoint(new BigInteger(1, x), new BigInteger(1, y));
        } else {
            throw new InvalidKeyException("Unsupported or invalid public EC point encoding");
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        Key osslKey;
        try {
            osslKey = this.engineTranslateKey(key);
        } catch (InvalidKeyException var4) {
            throw new InvalidKeySpecException(var4);
        }

        if (osslKey instanceof ECPublicKey) {
            if (keySpec != null && keySpec.isAssignableFrom(ECPublicKeySpec.class)) {
                return keySpec.cast(new ECPublicKeySpec(((ECPublicKey) osslKey).getW(), ((ECPublicKey) osslKey).getParams()));
            }
            if (keySpec != null && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(osslKey.getEncoded()));
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either ECPublicKeySpec or X509EncodedKeySpec");
            }
        } else if (osslKey instanceof ECPrivateKey) {
            if (keySpec != null && keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] der = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(der));
                } finally {
                    clearArray(der);
                }
            } else if (keySpec != null && keySpec.isAssignableFrom(ECPrivateKeySpec.class)) {
                return keySpec.cast(new ECPrivateKeySpec(((ECPrivateKey) osslKey).getS(), ((ECPrivateKey) osslKey).getParams()));
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either PKCS8EncodedKeySpec or ECPrivateKeySpec");
            }
        } else {
            throw new InvalidKeySpecException("Could not getKeySpec for given key");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof JceEcPublicKey || key instanceof JceEcPrivateKey) {
            return key;
        } else if (key instanceof PrivateKey) {
            return translatePrivate((PrivateKey) key);
        } else if (key instanceof PublicKey) {
            return translatePublic((PublicKey) key);
        } else {
            throw new InvalidKeyException("Could not translate to EC key");
        }
    }
}
