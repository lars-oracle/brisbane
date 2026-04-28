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

package com.oracle.test.integration.keyfactory;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.DSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.fail;

public class RsaKeyFactoryNegTest {

    KeyPairTestData kp;
    KeyFactory kf;

    @Before
    public void setUp() throws Exception {
        kp = TestData.getFirst(KeyPairTestData.class, alg("RSA"));
        kf = ProviderUtil.getKeyFactory("RSA");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generateRsaPrivateKeySpec() throws Exception {
        kf.generatePrivate(new RSAPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getD())));

    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateBadSpec() throws Exception {
        kf.generatePrivate(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicBadSpec() throws Exception {
        kf.generatePublic(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubNull() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, null);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubInvalid() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, RSAPrivateKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPriNull() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, null);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPrivInvalid() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, RSAPublicKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecNotRSAKey() throws Exception {
        X509EncodedKeySpec spec = kf.getKeySpec(new SecretKeySpec(new byte[16], "AES"), X509EncodedKeySpec.class);
    }

    @Test(expected = InvalidKeyException.class)
    public void translateNotAsymmetric() throws Exception {
        kf.translateKey(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected = InvalidKeyException.class)
    public void translateNotRSA() throws Exception {
        DSAPrivateKey dsaPriv = KeyUtil.getDummyDsaPrivateKey(new byte[0]);
        kf.translateKey(dsaPriv);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateNullSpecValue() throws Exception {
        PrivateKey privKey = kf.generatePrivate(new RSAPrivateCrtKeySpec(
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE()),
                null,
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getExpP()),
                new BigInteger(1, kp.getKeyParts().getExpQ()),
                new BigInteger(1, kp.getKeyParts().getCrtCoeff())));
    }
    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicNullSpecValue() throws Exception {
        PublicKey publKey = kf.generatePublic(new RSAPublicKeySpec(
                null, new BigInteger(1, kp.getKeyParts().getE())));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicZeroSpecValue() throws Exception {
        PublicKey publKey = kf.generatePublic(new RSAPublicKeySpec(
                new BigInteger(1, kp.getKeyParts().getN()),
                BigInteger.ZERO));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateBadSpecZeroValue() throws Exception {
        PrivateKey privKey = kf.generatePrivate(new RSAPrivateCrtKeySpec(
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE()),
                BigInteger.ZERO,
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getExpP()),
                new BigInteger(1, kp.getKeyParts().getExpQ()),
                new BigInteger(1, kp.getKeyParts().getCrtCoeff())));
    }

    @Test(expected = InvalidKeyException.class)
    public void translateBadKeyComponentZeroValue() throws Exception {
        PrivateKey privKey = getPrivateKeyWithOnlyModulusAndPrivateExponent();
        kf.translateKey(privKey);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateBadPkcs8ZeroValue() throws Exception {
        byte[] encoding = getPrivateKeyWithOnlyModulusAndPrivateExponent().getEncoded();
        kf.generatePrivate(new PKCS8EncodedKeySpec(encoding));
    }

    PrivateKey getPrivateKeyWithOnlyModulusAndPrivateExponent() {
        try {
            // Generate an RSA private key, using the 'SunRsaSign' provider, that only includes the
            // modulus (N) and private exponent (D) [does not have public exponent, prime factors or CRT information].
            RSAPrivateKeySpec keySpec = new RSAPrivateKeySpec(
                    new BigInteger(1, kp.getKeyParts().getN()),
                    new BigInteger(1, kp.getKeyParts().getD()));
            KeyFactory keyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
            return keyFactory.generatePrivate(keySpec);
        } catch (Exception e) {
            throw new RuntimeException(e);
        }
    }

    @Test
    public void invalidPrivateKeyComponents() throws Exception {
        KeyFactory sunRsaSignKeyFactory = KeyFactory.getInstance("RSA", "SunRsaSign");
        BigInteger[] valid = new BigInteger[]{
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE()),
                new BigInteger(1, kp.getKeyParts().getD()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getExpP()),
                new BigInteger(1, kp.getKeyParts().getExpQ()),
                new BigInteger(1, kp.getKeyParts().getCrtCoeff())
        };

        for (InvalidComponent invalid : InvalidComponent.values()) {
            for (int i = 0; i < valid.length; i++) {
                BigInteger[] bi = valid.clone();
                bi[i] = invalid == InvalidComponent.NULL ? null : invalid == InvalidComponent.ZERO ? BigInteger.ZERO : bi[i].negate();
                RSAPrivateCrtKeySpec keySpec =
                        new RSAPrivateCrtKeySpec(bi[0], bi[1], bi[2], bi[3], bi[4], bi[5], bi[6], bi[7]);

                try {
                    kf.generatePrivate(keySpec);
                    fail("Should have thrown InvalidKeySpecException");
                } catch (InvalidKeySpecException e) {
                    // Ignore - expected exception
                }

                // The SunRSASign provider will not encode null parameters or a modulus(i=0) less than 512-bits
                if (invalid != InvalidComponent.NULL && !(invalid == InvalidComponent.ZERO && i == 0)) {
                    PrivateKey privateKey = sunRsaSignKeyFactory.generatePrivate(keySpec);
                    byte[] encodedKey = privateKey.getEncoded();
                    try {
                        kf.generatePrivate(new PKCS8EncodedKeySpec(encodedKey));
                        fail("Should have thrown InvalidKeySpecException");
                    } catch (InvalidKeySpecException e) {
                        // Ignore - expected exception
                    }

                    try {
                        kf.translateKey(privateKey);
                        fail("Should have thrown InvalidKeyException");
                    } catch (InvalidKeyException e) {
                        // Ignore - expected exception
                    }
                }
            }
        }
    }

    @Test
    public void invalidPublicKeyComponents() throws Exception {
        BigInteger[] valid =  new BigInteger[] {
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE())
        };

        for (InvalidComponent invalid : InvalidComponent.values()) {
            for (int i = 0; i < valid.length; i++) {
                BigInteger[] bi = valid.clone();
                bi[i] = invalid == InvalidComponent.NULL ? null : invalid == InvalidComponent.ZERO ? BigInteger.ZERO : bi[i].negate();
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(bi[0], bi[1]);

                try {
                    kf.generatePublic(keySpec);
                    fail("Should have thrown InvalidKeySpecException");
                } catch (InvalidKeySpecException e) {
                    // Ignore - expected exception
                }

                // It is not convenient to test asn.1 decode of null, zero or negative values as the
                // SunRSASign provider will not encode null parameters, a modulus(i=0) less than 512-bits
                // a public exponent(i=1) less than 3 or a public exponent larger than the modulus
            }
        }
    }

    private enum InvalidComponent {NULL, ZERO, NEGATIVE}
}
