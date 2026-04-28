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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.key.JceRsaPrivateKey;
import com.oracle.jipher.internal.key.JceRsaPublicKey;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.common.InputChecks.isNullOrZeroOrNegative;
import static com.oracle.jipher.internal.common.Util.clearArray;
import static com.oracle.jipher.internal.common.Util.clearArrays;

/**
 * {@link java.security.KeyFactorySpi} implementation for RSA keys.
 */
public final class RsaKeyFactory extends AsymKeyFactory {

    private static final Asn1BerValue ID_RSA_ENCRYPTION = newOid("1.2.840.113549.1.1.1");

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof RSAPrivateCrtKeySpec spec) {
            if (isNullOrZeroOrNegative(spec.getModulus(), spec.getPublicExponent(), spec.getPrivateExponent(),
                    spec.getPrimeP(), spec.getPrimeQ(),
                    spec.getPrimeExponentP(), spec.getPrimeExponentQ(), spec.getCrtCoefficient())) {
                throw new InvalidKeySpecException("Parameter spec must not contain null, zero, or negative values");
            }
            try {
                return generatePrivateInternal(spec);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else if (keySpec instanceof RSAPrivateKeySpec) {
            throw new InvalidKeySpecException("RSA private key without CRT info not supported.");
        } else {
            return super.engineGeneratePrivate(keySpec);
        }
    }

    PrivateKey generatePrivateInternal(RSAPrivateCrtKeySpec spec) throws InvalidKeyException {
        return new JceRsaPrivateKey(Pkey.newRsaPriv(spec));
    }

    PrivateKey generatePrivateInternal(byte[] mod, byte[] e, byte[] d, byte[] p, byte[] q,
                                       byte[] primeExpP, byte[] primeExpQ, byte[] crtCoeff) throws InvalidKeyException {
        return new JceRsaPrivateKey(Pkey.newRsaPriv(mod, e, d, p, q, primeExpP, primeExpQ, crtCoeff));
    }

    @Override
    PrivateKey generatePrivateInternal(byte[] privDer) throws InvalidKeyException {
        byte[][] rsaPrivKey = null;
        try {
            rsaPrivKey = rsaPrivDerDecode(privDer);
            if (isNullOrZeroOrNegative(rsaPrivKey)) {
                throw new InvalidKeyException("Key must not contain a null, zero, or negative component");
            }
            return generatePrivateInternal(
                    rsaPrivKey[0], rsaPrivKey[1], rsaPrivKey[2], rsaPrivKey[3],
                    rsaPrivKey[4], rsaPrivKey[5], rsaPrivKey[6], rsaPrivKey[7]);
        } finally {
            clearArrays(rsaPrivKey);
        }
    }

    /**
     * Decode the DER-encoded RSA private key into an array of byte[]s containing the data elements
     * of the RSA private key.
     *
     * <p> The decoded array will contain eight values:
     * <ol>
     *     <li>modulus,</li>
     *     <li>public exponent,</li>
     *     <li>private exponent,</li>
     *     <li>prime factor p,</li>
     *     <li>prime factor q,</li>
     *     <li>prime exponent p,</li>
     *     <li>prime exponent q and</li>
     *     <li>the chinese remainder theorem coefficient</li>
     * </ol>
     * @param privDer the DER-encoded RSA private key data
     * @return an array of byte[]s containing the data elements of the RSA private key, each encoded as a
     *         two's-complement representation of an Integer in big-endian byte-order without any redundant
     *         leading bytes
     */
    private static byte[][] rsaPrivDerDecode(byte[] privDer) throws InvalidKeyException {
        try {
            // PrivateKeyInfo
            Asn1BerValue rsaPrivKey = Asn1.decodeOne(privDer).count(3).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> rsaPrivKeyValues = rsaPrivKey.sequence();

            // version Version
            BigInteger privKeyInfoVer = rsaPrivKeyValues.get(0).getInteger();
            if (!privKeyInfoVer.equals(BigInteger.ZERO)) {
                throw new Asn1DecodeException("Invalid PrivateKeyInfo version; was: " + privKeyInfoVer + ", expected: 0");
            }

            // privateKeyAlgorithm PrivateKeyAlgorithmIdentifier
            List<Asn1BerValue> algId = rsaPrivKeyValues.get(1).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (!algorithm.equals(ID_RSA_ENCRYPTION)) {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() + ", expected: " + ID_RSA_ENCRYPTION.getOid());
            }
            // parameters ANY OPTIONAL
            algId.get(1).getNull();

            // privateKey OCTET STRING
            // RSAPrivateKey
            Asn1BerValue rsaPrivateKey = Asn1.decodeOne(rsaPrivKeyValues.get(2).getOctetString())
                    .count(9).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> keyValues = rsaPrivateKey.sequence();

            // version Version
            BigInteger rsaPrivKeyVer = rsaPrivKeyValues.get(0).getInteger();
            if (!rsaPrivKeyVer.equals(BigInteger.ZERO)) {
                throw new Asn1DecodeException("Invalid RSAPrivateKey version; was: " + rsaPrivKeyVer + ", expected: 0");
            }

            byte[][] values = null;
            try {
                values = keyValues.stream().skip(1).map(Asn1BerValue::getIntegerOctets).toArray(byte[][]::new);
                return values;
            } catch (Exception e) {
                clearArrays(values);
                throw e;
            }
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode RSA Private Key", ex);
        }
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof RSAPublicKeySpec rsaSpec) {
            if (isNullOrZeroOrNegative(rsaSpec.getModulus(), rsaSpec.getPublicExponent())) {
                throw new InvalidKeySpecException("Parameter spec must not contain null, zero, or negative values");
            }
            try {
                return generatePublicInternal(rsaSpec.getModulus(), rsaSpec.getPublicExponent(), null);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePublic(keySpec);
        }
    }

    PublicKey generatePublicInternal(BigInteger mod, BigInteger e, byte[] pubDer) throws InvalidKeyException {
        Pkey pkey = Pkey.newRsaPub(mod, e);
        return new JceRsaPublicKey(pkey, mod, e, pubDer);
    }

    @Override
    PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException {
        BigInteger[] rsaPubKey = rsaPubDerDecode(pubDer);
        if (isNullOrZeroOrNegative(rsaPubKey)) {
            throw new InvalidKeyException("Key must not contain a null, zero, or negative component");
        }
        return generatePublicInternal(rsaPubKey[0], rsaPubKey[1], pubDer);
    }

    /**
     * Decode the DER-encoded RSA public key into a {@link BigInteger} array containing
     * the modulus and public exponent.
     *
     * @param pubDer the DER-encoded RSA public key data
     * @return the {@link BigInteger} array with the modulus and public exponent
     */
    private static BigInteger[] rsaPubDerDecode(byte[] pubDer) throws InvalidKeyException {
        try {
            // SubjectPublicKeyInfo
            Asn1BerValue rsaPubKey = Asn1.decodeOne(pubDer).count(2).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> rsaPubKeyValues = rsaPubKey.sequence();

            // AlgorithmIdentifier
            List<Asn1BerValue> algId = rsaPubKeyValues.get(0).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (!algorithm.equals(ID_RSA_ENCRYPTION)) {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() + ", expected: " + ID_RSA_ENCRYPTION.getOid());
            }
            // parameters ANY OPTIONAL
            algId.get(1).getNull();

            // subjectPublicKey BIT STRING
            // RSAPublicKey
            Asn1BerValue rsaPublicKey = Asn1.decodeOne(rsaPubKeyValues.get(1).getBitStringOctets())
                    .count(2).tagClassDeep(UNIVERSAL);
            return rsaPublicKey.sequence().stream().map(Asn1BerValue::getInteger).toArray(BigInteger[]::new);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode RSA Public Key", ex);
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

        if (osslKey instanceof RSAPublicKey pub) {
            if (keySpec != null && keySpec.isAssignableFrom(RSAPublicKeySpec.class)) {
                // JceRsaPublicKey implements RSAPublicKey
                return keySpec.cast(new RSAPublicKeySpec(pub.getModulus(), pub.getPublicExponent()));
            } else if (keySpec != null && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(osslKey.getEncoded()));
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either X509EncodedKeySpec or RSAPublicKeySpec");
            }
        } else if (osslKey instanceof RSAPrivateKey) {
            if (keySpec != null && keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] privDer = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(privDer));
                } finally {
                    clearArray(privDer);
                }
            } else if (keySpec != null && keySpec.isAssignableFrom(RSAPrivateCrtKeySpec.class)) {
                // JceRsaPrivateKey implements RSAPrivateCrtKey
                RSAPrivateCrtKey prv = (RSAPrivateCrtKey) osslKey;
                return keySpec.cast(new RSAPrivateCrtKeySpec(
                        prv.getModulus(), prv.getPublicExponent(), prv.getPrivateExponent(),
                        prv.getPrimeP(), prv.getPrimeQ(),
                        prv.getPrimeExponentP(), prv.getPrimeExponentQ(), prv.getCrtCoefficient()
                ));
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either PKCS8EncodedKeySpec or RSAPrivateCrtKeySpec");
            }
        } else {
            throw new InvalidKeySpecException("Could not getKeySpec for given key");
        }
    }

    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof JceRsaPublicKey || key instanceof JceRsaPrivateKey) {
            return key;
        } else if (key instanceof PrivateKey) {
            return translatePrivate((PrivateKey) key);
        } else if (key instanceof PublicKey) {
            return translatePublic((PublicKey) key);
        } else {
            throw new InvalidKeyException("Could not translate to RSA key");
        }
    }

}
