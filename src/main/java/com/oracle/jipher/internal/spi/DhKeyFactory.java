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
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.asn1.UniversalTag;
import com.oracle.jipher.internal.key.JceDhPrivateKey;
import com.oracle.jipher.internal.key.JceDhPublicKey;
import com.oracle.jipher.internal.openssl.Pkey;
import com.oracle.jipher.internal.spi.DHExtendedPrivateKeySpec;
import com.oracle.jipher.internal.spi.DHExtendedPublicKeySpec;
import com.oracle.jipher.internal.spi.DHFIPSParameterSpec;
import com.oracle.jipher.internal.spi.DHFIPSParameterValidationSpec;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.common.InputChecks.isNullOrZeroOrNegative;
import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * KeyFactorySpi implementation for DH keys.
 */
public final class DhKeyFactory extends AsymKeyFactory {

    private static final Asn1BerValue ID_DH_KEY_AGREEMENT = newOid("1.2.840.113549.1.3.1");
    private static final Asn1BerValue ID_DH_PUBLIC_NUMBER = newOid("1.2.840.10046.2.1");

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof DHPrivateKeySpec dhPrivateKeySpec) {
            DHParameterSpec dhParamSpec;
            if (dhPrivateKeySpec instanceof DHExtendedPrivateKeySpec) {
                dhParamSpec = ((DHExtendedPrivateKeySpec) dhPrivateKeySpec).getParams();
            } else {
                dhParamSpec = new DHParameterSpec(dhPrivateKeySpec.getP(), dhPrivateKeySpec.getG());
            }
            BigInteger x = dhPrivateKeySpec.getX();

            if (isNullOrZeroOrNegative(dhParamSpec.getP(), dhParamSpec.getG(), x)) {
                throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
            }
            if (dhParamSpec instanceof DHFIPSParameterSpec dhFipsParameterSpec) {
                if (isNullOrZeroOrNegative(dhFipsParameterSpec.getQ())) {
                    throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
                }
            }

            try {
                Pkey pkey = Pkey.newDhPriv(dhParamSpec, x);
                return new JceDhPrivateKey(pkey, dhParamSpec);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePrivate(keySpec);
        }
    }

    PrivateKey generatePrivateInternal(byte[] priv, DHParameterSpec spec) throws InvalidKeyException {
        Pkey pkey = Pkey.newDhPriv(spec, priv);
        return new JceDhPrivateKey(pkey, spec);
    }

    @Override
    PrivateKey generatePrivateInternal(byte[] privDer) throws InvalidKeyException {
        byte[] privKey = null;
        try {
            Object[] dhParamSpecAndPrivateKey = dhPrivDerDecode(privDer);
            DHParameterSpec dhParameterSpec = (DHParameterSpec) dhParamSpecAndPrivateKey[0];
            privKey = (byte[]) dhParamSpecAndPrivateKey[1];

            if (isNullOrZeroOrNegative(dhParameterSpec.getP(), dhParameterSpec.getG()) ||
                    isNullOrZeroOrNegative(privKey)) {
                throw new InvalidKeyException("Key must not contain null, zero, or negative values");
            }
            if (dhParameterSpec instanceof DHFIPSParameterSpec dhFipsParameterSpec) {
                if (isNullOrZeroOrNegative(dhFipsParameterSpec.getQ())) {
                    throw new InvalidKeyException("Key spec must not contain null, zero, or negative values");
                }
            }

            return generatePrivateInternal(privKey, dhParameterSpec);
        } finally {
            clearArray(privKey);
        }
    }

    /**
     * Decode the DER-encoded DH private key into a DHParameterSpec containing the DH parameters and
     * a byte[] containing the DH private key as a 2's-complement Integer in big-endian byte-order:
     * the most significant byte is in the zeroth element.
     * Supports decoding DH private keys encoded in PKCS #8 Private-Key Information Syntax - see RFC-5208 section 5.
     *  Note PrivateKeyAlgorithmIdentifier is defined as AlgorithmIdentifier is defined in CCITT. Recommendation X.509
     *  Supports two possible privateKeyAlgorithm algorithm IDs -
     *      either:
     *          {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-3(3) dhKeyAgreement(1)}
     *              in which case the AlgorithmIdentifier parameters are decoded according to PKCS #3 section 9.
     *      OR
     *          {iso(1) member-body(2) us(840) ansi-x942(10046) number-types(2) dhpublicnumber(1)}
     *              in which case the AlgorithmIdentifier parameters are decoded according to RFC 3279 section-2.3.3
     *
     * @param privDer the DER-encoded DH private key data
     * @return a 2 element array of Objects - A DHParameterSpec containing the DH parameters and
     *         a byte[] containing the DH private key as a 2's-complement Integer in big-endian byte-order:
     *         the most significant byte is in the zeroth element
     */
    private static Object[] dhPrivDerDecode(byte[] privDer) throws InvalidKeyException {
        try {
            DHParameterSpec dhParamSpec;

            // PrivateKeyInfo
            Asn1BerValue dhPrivKey = Asn1.decodeOne(privDer).count(3).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> dhPrivKeyValues = dhPrivKey.sequence();

            // version Version
            BigInteger privKeyInfoVer = dhPrivKeyValues.get(0).getInteger();
            if (!privKeyInfoVer.equals(BigInteger.ZERO)) {
                throw new Asn1DecodeException("Invalid PrivateKeyInfo version; was: " + privKeyInfoVer + ", expected: 0");
            }

            // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
            List<Asn1BerValue> algId = dhPrivKeyValues.get(1).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (algorithm.equals(ID_DH_KEY_AGREEMENT)) {
                dhParamSpec = dhPkcs3DomainParametersDecode(algId.get(1));
            } else if (algorithm.equals(ID_DH_PUBLIC_NUMBER)) {
                dhParamSpec = dhX509DomainParametersDecode(algId.get(1));
            }
            else {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() +
                        ", expected: " + ID_DH_KEY_AGREEMENT + " or " + ID_DH_PUBLIC_NUMBER);
            }

            // privateKey OCTET STRING
            byte[] dhPrivateKey = Asn1.decodeOne(dhPrivKeyValues.get(2).getOctetString()).getIntegerOctets();

            return new Object[] {dhParamSpec, dhPrivateKey};
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode DH Private Key", ex);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof DHPublicKeySpec dhPublicKeySpec) {
            DHParameterSpec dhParameterSpec;
            if (dhPublicKeySpec instanceof DHExtendedPublicKeySpec dhExtendedPublicKeySpec) {
                dhParameterSpec = dhExtendedPublicKeySpec.getParams();
            } else {
                dhParameterSpec = new DHParameterSpec(dhPublicKeySpec.getP(), dhPublicKeySpec.getG());
            }
            BigInteger y = dhPublicKeySpec.getY();

            if (isNullOrZeroOrNegative(dhParameterSpec.getP(), dhParameterSpec.getG(), y)) {
                throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
            }
            if (dhParameterSpec instanceof DHFIPSParameterSpec dhFipsParameterSpec) {
                if (isNullOrZeroOrNegative(dhFipsParameterSpec.getQ())) {
                    throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
                }
            }
            try {
                Pkey pkey = Pkey.newDhPub(dhParameterSpec, y);
                return new JceDhPublicKey(pkey, y, dhParameterSpec, null);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePublic(keySpec);
        }
    }

    PublicKey generatePublicInternal(DHExtendedPublicKeySpec spec, byte[] pubDer) throws InvalidKeyException {
        DHParameterSpec dhParamSpec = spec.getParams();
        BigInteger y = spec.getY();
        Pkey pkey = Pkey.newDhPub(dhParamSpec, y);
        return new JceDhPublicKey(pkey, y, dhParamSpec, pubDer);
    }

    @Override
    PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException {
        DHExtendedPublicKeySpec keySpec = dhPubDerDecode(pubDer);
        if (isNullOrZeroOrNegative(keySpec.getP(), keySpec.getG(), keySpec.getY())) {
            throw new InvalidKeyException("Key must not contain null, zero, or negative values");
        }
        return generatePublicInternal(keySpec, pubDer);
    }

    /**
     * Decode the DER-encoded DH public key into a DHExtendedPublicKeySpec.
     *  Supports decoding DH public keys encoded as:
     *      PublicKeyInfo ::= SEQUENCE {
     *          publicKeyAlgorithm  AlgorithmIdentifier
     *          publicKey           BIT STRING }
     *  , see RFC 5208, where AlgorithmIdentifier is defined in CCITT. Recommendation X.509
     *  Supports two possible publicKeyAlgorithm algorithm IDs -
     *      either:
     *          {iso(1) member-body(2) us(840) rsadsi(113549) pkcs(1) pkcs-3(3) dhKeyAgreement(1)}
     *              in which case the AlgorithmIdentifier parameters are decoded according to PKCS #3 section 9.
     *      OR
     *          {iso(1) member-body(2) us(840) ansi-x942(10046) number-types(2) dhpublicnumber(1)}
     *              in which case the AlgorithmIdentifier parameters are decoded according to RFC 3279 section-2.3.3
     *
     * @param pubDer the DER-encoded DH public key data
     * @return the DHExtendedPublicKeySpec
     */
    private static DHExtendedPublicKeySpec dhPubDerDecode(byte[] pubDer) throws InvalidKeyException {
        try {
            DHParameterSpec dhParamSpec;

            // SubjectPublicKeyInfo
            Asn1BerValue dhPubKey = Asn1.decodeOne(pubDer).count(2).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> dhPubKeyValues = dhPubKey.sequence();

            // AlgorithmIdentifier
            List<Asn1BerValue> algId = dhPubKeyValues.get(0).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (algorithm.equals(ID_DH_KEY_AGREEMENT)) {
                dhParamSpec = dhPkcs3DomainParametersDecode(algId.get(1));
            } else if (algorithm.equals(ID_DH_PUBLIC_NUMBER)) {
                dhParamSpec = dhX509DomainParametersDecode(algId.get(1));
            }
             else {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() +
                        ", expected: " + ID_DH_KEY_AGREEMENT + " or " + ID_DH_PUBLIC_NUMBER);
            }

            // subjectPublicKey BIT STRING
            // DHPublicKey ::= INTEGER -- public key, Y
            BigInteger y = Asn1.decodeOne(dhPubKeyValues.get(1).getBitStringOctets()).getInteger();

            return new DHExtendedPublicKeySpec(y, dhParamSpec);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode DH Public Key", ex);
        }
    }

    @Override
    protected <T extends KeySpec> T engineGetKeySpec(Key key, Class<T> keySpec) throws InvalidKeySpecException {
        Key osslKey;
        try {
            osslKey = this.engineTranslateKey(key);
        } catch (InvalidKeyException e) {
            throw new InvalidKeySpecException(e);
        }

        if (osslKey instanceof DHPublicKey) {
            if (keySpec != null && keySpec.isAssignableFrom(DHPublicKeySpec.class)) {
                DHParameterSpec dhParams = ((DHPublicKey) osslKey).getParams();
                return keySpec.cast(new DHPublicKeySpec(((DHPublicKey) osslKey).getY(), dhParams.getP(), dhParams.getG()));
            } else if (keySpec != null && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(osslKey.getEncoded()));
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either DHPublicKeySpec or X509EncodedKeySpec");
            }
        } else if (osslKey instanceof DHPrivateKey) {
            if (keySpec != null &&  keySpec.isAssignableFrom(DHPrivateKeySpec.class)) {
                DHParameterSpec dhParams = ((DHPrivateKey) osslKey).getParams();
                return keySpec.cast(new DHPrivateKeySpec(((DHPrivateKey) osslKey).getX(), dhParams.getP(), dhParams.getG()));
            } else if (keySpec != null && keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] der = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(der));
                } finally {
                    clearArray(der);
                }
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either DHPrivateKeySpec or PKCS8EncodedKeySpec");
            }
        } else {
            throw new InvalidKeySpecException("Could not getKeySpec for given key");
        }
    }


    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof JceDhPublicKey || key instanceof JceDhPrivateKey) {
            return key;
        } else if (key instanceof PrivateKey) {
            return translatePrivate((PrivateKey) key);
        } else if (key instanceof PublicKey) {
            return translatePublic((PublicKey) key);
        } else {
            throw new InvalidKeyException("Could not translate to DH key");
        }
    }


    /**
     * Decode the Asn1 encoded PKCS #3 DH Parameters into a DHParameterSpec.  See PKCS #3 section 9.
     *
     * @param dhParam the Asn1 encoded PKCS #3 DH Parameters
     * @return the DHParameterSpec
     */
    private static DHParameterSpec dhPkcs3DomainParametersDecode(Asn1BerValue dhParam) {
        List<Asn1BerValue> dhParamValues = dhParam.count(2, 3).sequence();
        BigInteger p = dhParamValues.get(0).getInteger();
        BigInteger g = dhParamValues.get(1).getInteger();
        BigInteger privateValueLength = (dhParamValues.size() > 2) ? dhParamValues.get(2).getInteger() : null;

        int length = privateValueLength == null ? 0 : privateValueLength.intValue();
        return new DHParameterSpec(p, g, length);
    }

    /**
     * Decode the Asn1 encoded X.509 DH Parameters into a DHParameterSpec. See RFC 3279 section 2.3.3.
     *
     * @param dhParam the Asn1 encoded X.509 DH Parameters
     * @return the DHParameterSpec
     */
    private static DHParameterSpec dhX509DomainParametersDecode(Asn1BerValue dhParam) {
        List<Asn1BerValue> dhParamValues = dhParam.count(3, 5).sequence();
        BigInteger p = dhParamValues.get(0).getInteger();
        BigInteger g = dhParamValues.get(1).getInteger();
        BigInteger q = dhParamValues.get(2).getInteger();

        // Process optional parameters
        BigInteger j = null;
        DHFIPSParameterValidationSpec validationParamSpec = null;

        int numParams = dhParamValues.size();
        if (numParams == 4) { // either j or validationParams is not present
            Asn1BerValue param = dhParamValues.get(3);
            // If integer, this is j
            if (param.hasTag(UniversalTag.INTEGER)) {
                j = param.getInteger();
            } else { // else, this is validationParms
                List<Asn1BerValue> validationParms = param.count(2).sequence();
                validationParamSpec = new DHFIPSParameterValidationSpec(
                        validationParms.get(0).getBitStringOctets(),
                        validationParms.get(1).getInteger().intValue());
            }
        } else if (numParams == 5) {
            j =  dhParamValues.get(3).getInteger();

            List<Asn1BerValue> validationParms = dhParamValues.get(4).count(2).sequence();
            validationParamSpec = new DHFIPSParameterValidationSpec(
                    validationParms.get(0).getBitStringOctets(),
                    validationParms.get(1).getInteger().intValue());
        }

        return new DHFIPSParameterSpec(p, q, g, j, validationParamSpec);
    }
}
