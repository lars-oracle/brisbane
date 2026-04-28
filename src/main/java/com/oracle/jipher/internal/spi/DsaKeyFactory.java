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
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAParameterSpec;
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.List;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.key.JceDsaPublicKey;
import com.oracle.jipher.internal.openssl.Pkey;

import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;
import static com.oracle.jipher.internal.common.InputChecks.isNullOrZeroOrNegative;
import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link java.security.KeyFactorySpi} for DSA keys.
 */
public final class DsaKeyFactory extends AsymKeyFactory {

    private static final Asn1BerValue ID_DSA = newOid("1.2.840.10040.4.1");

    @Override
    protected PrivateKey engineGeneratePrivate(KeySpec keySpec) {
        // This method should never be called because DSA Key Pair generation is not supported.
        throw new UnsupportedOperationException("DSA private key generation not supported");
    }

    @Override
    PrivateKey generatePrivateInternal(byte[] privDer) {
        throw new UnsupportedOperationException("DSA private key generation not supported");
    }

    @Override
    protected PublicKey engineGeneratePublic(KeySpec keySpec) throws InvalidKeySpecException {
        if (keySpec instanceof DSAPublicKeySpec dsaPublicKeySpec) {
            if (isNullOrZeroOrNegative(dsaPublicKeySpec.getP(), dsaPublicKeySpec.getQ(), dsaPublicKeySpec.getG(),
                    dsaPublicKeySpec.getY())) {
                throw new InvalidKeySpecException("Key spec must not contain null, zero, or negative values");
            }
            try {
                return generatePublicInternal(dsaPublicKeySpec, null);
            } catch (InvalidKeyException e) {
                throw new InvalidKeySpecException(e);
            }
        } else {
            return super.engineGeneratePublic(keySpec);
        }
    }

    PublicKey generatePublicInternal(DSAPublicKeySpec spec, byte[] pubDer) throws InvalidKeyException {
        DSAParameterSpec dsaParameterSpec = new DSAParameterSpec(spec.getP(), spec.getQ(), spec.getG());
        Pkey pkey = Pkey.newDsaPub(dsaParameterSpec, spec.getY());
        return new JceDsaPublicKey(pkey, spec.getY(), dsaParameterSpec, pubDer);
    }

    @Override
    PublicKey generatePublicInternal(byte[] pubDer) throws InvalidKeyException {
        DSAPublicKeySpec keySpec = dsaPubDerDecode(pubDer);
        if (isNullOrZeroOrNegative(keySpec.getP(), keySpec.getQ(), keySpec.getG(), keySpec.getY())) {
            throw new InvalidKeyException("Key must not contain null, zero, or negative values");
        }
        return generatePublicInternal(keySpec, pubDer);
    }

    /**
     * Decode the DER-encoded DSA public key into a DSAPublicKeySpec.
     *
     * @param pubDer the DER-encoded DSA public key data
     * @return the DSAPublicKeySpec
     */
    private static DSAPublicKeySpec dsaPubDerDecode(byte[] pubDer) throws InvalidKeyException {
        try {
            // SubjectPublicKeyInfo
            Asn1BerValue dsaPubKey = Asn1.decodeOne(pubDer).count(2).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> dsaPubKeyValues = dsaPubKey.sequence();

            // AlgorithmIdentifier
            List<Asn1BerValue> algId = dsaPubKeyValues.get(0).count(2).sequence();
            // algorithm OBJECT IDENTIFIER
            Asn1BerValue algorithm = algId.get(0);
            if (!algorithm.equals(ID_DSA)) {
                throw new Asn1DecodeException("Unsupported key algorithm; was: " + algorithm.getOid() + ", expected: " + ID_DSA.getOid());
            }
            // parameters ANY OPTIONAL
            // Dss-Parms
            List<Asn1BerValue> dsaParamValues = algId.get(1).count(3).sequence();
            BigInteger p = dsaParamValues.get(0).getInteger();
            BigInteger q = dsaParamValues.get(1).getInteger();
            BigInteger g = dsaParamValues.get(2).getInteger();

            // subjectPublicKey BIT STRING
            // DSAPublicKey ::= INTEGER -- public key, Y
            BigInteger y = Asn1.decodeOne(dsaPubKeyValues.get(1).getBitStringOctets()).getInteger();
            return new DSAPublicKeySpec(y, p, q, g);
        } catch (Asn1DecodeException ex) {
            throw new InvalidKeyException("Unable to decode DSA Public Key", ex);
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

        if (osslKey instanceof DSAPublicKey) {
            if (keySpec != null && keySpec.isAssignableFrom(DSAPublicKeySpec.class)) {
                DSAParams dsaParams = ((DSAPublicKey) osslKey).getParams();
                return keySpec.cast(new DSAPublicKeySpec(((DSAPublicKey) osslKey).getY(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));
            } else if (keySpec != null && keySpec.isAssignableFrom(X509EncodedKeySpec.class)) {
                return keySpec.cast(new X509EncodedKeySpec(osslKey.getEncoded()));
            }  else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either DSAPublicKeySpec or X509EncodedKeySpec");
            }
        } else if (osslKey instanceof DSAPrivateKey) {
            if (keySpec != null && keySpec.isAssignableFrom(DSAPrivateKeySpec.class)) {
                DSAParams dsaParams = ((DSAPrivateKey) osslKey).getParams();
                return keySpec.cast(new DSAPrivateKeySpec(((DSAPrivateKey) osslKey).getX(), dsaParams.getP(), dsaParams.getQ(), dsaParams.getG()));
            } else if (keySpec != null && keySpec.isAssignableFrom(PKCS8EncodedKeySpec.class)) {
                byte[] der = key.getEncoded();
                try {
                    return keySpec.cast(new PKCS8EncodedKeySpec(der));
                } finally {
                    clearArray(der);
                }
            } else {
                throw new InvalidKeySpecException("Expected KeySpec class to be assignable from either DSAPrivateKeySpec or PKCS8EncodedKeySpec");
            }
        } else {
            throw new InvalidKeySpecException("Could not getKeySpec for given key");
        }
    }


    @Override
    protected Key engineTranslateKey(Key key) throws InvalidKeyException {
        if (key instanceof JceDsaPublicKey) {
            return key;
        } else if (key instanceof PrivateKey) {
            return translatePrivate((PrivateKey) key);
        } else if (key instanceof PublicKey) {
            return translatePublic((PublicKey) key);
        } else {
            throw new InvalidKeyException("Could not translate to DSA key");
        }
    }
}
