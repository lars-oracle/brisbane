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

package com.oracle.test.integration;

import java.math.BigInteger;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAParams;
import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.SecretKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.keyfactory.EcParamTestUtil;

public class KeyUtil {

    public static PrivateKey loadPrivate(String alg, byte[] encoding) throws Exception {
        KeyFactory kf = ProviderUtil.getKeyFactory(alg);
        return kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
    }

    public static PublicKey loadPublic(String alg, byte[] encoding) throws Exception {
        KeyFactory kf = ProviderUtil.getKeyFactory(alg);
        return kf.generatePublic(new X509EncodedKeySpec(encoding));
    }

    public static PrivateKey duplicate(PrivateKey key) throws Exception {
        KeyFactory kf = ProviderUtil.getKeyFactory(key.getAlgorithm());
        return kf.generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
    }

    public static SecretKey getDummySecretKey(final String alg, final byte[] enc, final String format) {
        return new SecretKey() {
            @Override
            public String getAlgorithm() { return alg; }
            @Override
            public String getFormat() { return format; }
            @Override
            public byte[] getEncoded() { return enc.clone(); }
        };
    }

    public static PBEKey getDummyPBEKey(final String alg, final byte[] enc, final String format, final char[] pw, final byte[] salt, final int iter) {
        return new PBEKey() {
            @Override
            public String getAlgorithm() { return alg; }
            @Override
            public String getFormat() { return format; }
            @Override
            public byte[] getEncoded() { return enc != null ? enc.clone() : null; }
            @Override
            public char[] getPassword() { return pw != null ? pw.clone() : null; }
            @Override
            public byte[] getSalt() { return salt != null ? salt.clone() : null; }
            @Override
            public int getIterationCount() { return iter; }
        };
    }

    public static PublicKey getDummyPublicKey(byte[] encoding, Class specClass) {
        if (ECPublicKey.class.isAssignableFrom(specClass)) {
            return getDummyEcPublicKey(encoding);
        }
        if (DHPublicKey.class.isAssignableFrom(specClass)) {
            return getDummyDhPublicKey(encoding);
        }
        if (DSAPublicKey.class.isAssignableFrom(specClass)) {
            return getDummyDsaPublicKey(encoding);
        }
        if (RSAPublicKey.class.isAssignableFrom(specClass)) {
            return getDummyRsaPublicKey(encoding);
        }
        throw new Error("Unsupported dummy key class " + specClass);
    }
    public static PrivateKey getDummyPrivateKey(byte[] encoding, Class specClass) {
        if (ECPrivateKey.class.isAssignableFrom(specClass)) {
            return getDummyEcPrivateKey(encoding);
        }
        if (DHPrivateKey.class.isAssignableFrom(specClass)) {
            return getDummyDhPrivateKey(encoding);
        }
        if (DSAPrivateKey.class.isAssignableFrom(specClass)) {
            return getDummyDsaPrivateKey(encoding);
        }
        if (RSAPrivateKey.class.isAssignableFrom(specClass)) {
            return getDummyRsaPrivateKey(encoding);
        }
        throw new Error("Unsupported dummy key class " + specClass);
    }

    public static PublicKey getDummyPublicKey(final String alg, final byte[] encoding) {
        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return alg;
            }

            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return encoding;
            }
        };
    }

    public static RSAPublicKey getDummyRsaPublicKey(final byte[] enc) {
        return new RSAPublicKey() {
            @Override
            public BigInteger getPublicExponent() {
                return null;
            }

            @Override
            public String getAlgorithm() { return "RSA"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() {
                return enc;
            }

            @Override
            public BigInteger getModulus() {
                return null;
            }
        };
    }

    public static RSAPrivateKey getDummyRsaPrivateKey(final byte[] enc) {
        return new RSAPrivateCrtKey() {
            @Override
            public BigInteger getPublicExponent() { return null; }

            @Override
            public BigInteger getPrimeP() { return null; }

            @Override
            public BigInteger getPrimeQ() { return null; }

            @Override
            public BigInteger getPrimeExponentP() { return null; }

            @Override
            public BigInteger getPrimeExponentQ() { return null; }

            @Override
            public BigInteger getCrtCoefficient() { return null; }

            @Override
            public BigInteger getPrivateExponent() { return null; }

            @Override
            public String getAlgorithm() { return "RSA"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() { return enc; }

            @Override
            public BigInteger getModulus() { return null; }
        };
    }

    public static DSAPublicKey getDummyDsaPublicKey(final byte[] enc) {
        return new DSAPublicKey() {
            @Override
            public BigInteger getY() { return null; }

            @Override
            public String getAlgorithm() { return "DSA"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() { return enc; }

            @Override
            public DSAParams getParams() { return null; }
        };
    }

    public static DSAPrivateKey getDummyDsaPrivateKey(final byte[] enc) {
        return new DSAPrivateKey() {
            @Override
            public BigInteger getX() { return null; }

            @Override
            public String getAlgorithm() { return "DSA"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() { return enc; }

            @Override
            public DSAParams getParams() { return null; }
        };
    }

    public static DHPublicKey getDummyDhPublicKey(final byte[] enc) {
        return new DHPublicKey() {
            @Override
            public BigInteger getY() { return null; }

            @Override
            public String getAlgorithm() { return "DH"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() { return enc; }

            @Override
            public DHParameterSpec getParams() { return null; }
        };
    }

    public static DHPrivateKey getDummyDhPrivateKey(final byte[] enc) {
        return new DHPrivateKey() {
            @Override
            public BigInteger getX() { return null; }

            @Override
            public String getAlgorithm() { return "DH"; }

            @Override
            public String getFormat() { return null; }

            @Override
            public byte[] getEncoded() { return enc; }

            @Override
            public DHParameterSpec getParams() { return null; }
        };
    }

    public static PrivateKey getDummyPrivateKey(final String alg, final byte[] encoding) {
        return new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return alg;
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return encoding;
            }
        };
    }

    public static ECPrivateKey getDummyEcPrivateKey(final byte[] encoding) {
        return new ECPrivateKey() {

            @Override
            public BigInteger getS() {
                return null;
            }

            @Override
            public ECParameterSpec getParams() {
                return EcParamTestUtil.P224_PARAM_SPEC;
            }

            @Override
            public String getAlgorithm() {
                return "EC";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return encoding;
            }
        };
    }
    public static ECPublicKey getDummyEcPublicKey(final byte[] encoding) {
        return new ECPublicKey() {

            @Override
            public ECPoint getW() { return null; }

            @Override
            public ECParameterSpec getParams() {
                return EcParamTestUtil.P224_PARAM_SPEC;
            }

            @Override
            public String getAlgorithm() {
                return "EC";
            }

            @Override
            public String getFormat() {
                return "PKCS#8";
            }

            @Override
            public byte[] getEncoded() {
                return encoding;
            }
        };
    }
}
