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
import java.security.interfaces.ECPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.fail;

public class DhKeyFactoryNegTest {
    KeyPairTestData kp;
    KeyFactory kf;

    @Before
    public void setUp() throws Exception {
        kp = TestData.getFirst(KeyPairTestData.class, alg("DH").secParam("2048"));
        kf = ProviderUtil.getKeyFactory("DH");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubNull() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, null);
    }

    @Test(expected= InvalidKeySpecException.class)
    public void getKeySpecPubInvalid() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, DHPrivateKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPriNull() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, null);
    }

    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecPrivInvalid() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, DHPublicKeySpec.class);
    }

    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecNotECKey() throws Exception {
        X509EncodedKeySpec spec = kf.getKeySpec(new SecretKeySpec(new byte[16], "AES"), X509EncodedKeySpec.class);
    }

    @Test(expected = InvalidKeyException.class)
    public void translateNotAsymmetric() throws Exception {
        kf.translateKey(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected=InvalidKeyException.class)
    public void translateNotDSA() throws Exception {
        ECPrivateKey dsaPriv = KeyUtil.getDummyEcPrivateKey(new byte[0]);
        kf.translateKey(dsaPriv);
    }

    @Test(expected= InvalidKeySpecException.class)
    public void generatePrivateBadSpec() throws Exception {
        kf.generatePrivate(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected= InvalidKeySpecException.class)
    public void generatePublicBadSpec() throws Exception {
        kf.generatePublic(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicNullParameters() throws Exception {
        kf.generatePublic(new DHPublicKeySpec(
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                null));
    }
    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateNullParameters() throws Exception {
        kf.generatePrivate(new DHPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                null,
                new BigInteger(1, kp.getKeyParts().getG())));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateBadParameterValue() throws Exception {
        kf.generatePrivate(new DHPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                BigInteger.ZERO,
                new BigInteger(1, kp.getKeyParts().getG())));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicBadParameterValue() throws Exception {
        kf.generatePublic(new DHPrivateKeySpec(
                BigInteger.ZERO,
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getG())));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubKeyFailsToTranslate() throws Exception {
        PublicKey key = KeyUtil.getDummyDhPublicKey(new byte[14]);
        kf.getKeySpec(key, DHPublicKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPrivateKeyFailsToTranslate() throws Exception {
        PrivateKey key = KeyUtil.getDummyDhPrivateKey(new byte[14]);
        kf.getKeySpec(key, DHPrivateKeySpec.class);
    }

    @Test
    public void invalidPrivateKeyComponents() throws Exception {
        KeyFactory sunJceKeyFactory = KeyFactory.getInstance("DH", "SunJCE");
        BigInteger[] valid = new BigInteger[] {
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getG())
        };

        for (InvalidComponent invalid : InvalidComponent.values()) {
            for (int i = 0; i < valid.length; i++) {
                BigInteger[] bi = valid.clone();
                bi[i] = invalid == InvalidComponent.NULL ? null : invalid == InvalidComponent.ZERO ? BigInteger.ZERO : bi[i].negate();
                DHPrivateKeySpec keySpec = new DHPrivateKeySpec(bi[0], bi[1], bi[2]);

                try {
                    kf.generatePrivate(keySpec);
                    fail("Should have thrown InvalidKeySpecException");
                } catch (InvalidKeySpecException e) {
                    // Ignore - expected exception
                }

                // The SunJCE provider will not encode null parameters
                if (invalid != InvalidComponent.NULL) {
                    PrivateKey privateKey = sunJceKeyFactory.generatePrivate(keySpec);
                    byte[] encodedKey = privateKey.getEncoded();
                    try {
                        kf.generatePrivate(new X509EncodedKeySpec(encodedKey));
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
        KeyFactory sunJceKeyFactory = KeyFactory.getInstance("DH", "SunJCE");
        BigInteger[] valid =  new BigInteger[] {
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getG())
        };
        for (InvalidComponent invalid : InvalidComponent.values()) {
            for (int i = 0; i < valid.length; i++) {
                BigInteger[] bi = valid.clone();
                bi[i] = invalid == InvalidComponent.NULL ? null : invalid == InvalidComponent.ZERO ? BigInteger.ZERO : bi[i].negate();
                DHPublicKeySpec keySpec = new DHPublicKeySpec(bi[0], bi[1], bi[2]);

                try {
                    kf.generatePublic(keySpec);
                    fail("Should have thrown InvalidKeySpecException");
                } catch (InvalidKeySpecException e) {
                    // Ignore - expected exception
                }

                // The SunJCE provider will not encode null parameters
                if (invalid != InvalidComponent.NULL) {
                    PublicKey publicKey = sunJceKeyFactory.generatePublic(keySpec);
                    byte[] encodedKey = publicKey.getEncoded();
                    try {
                        kf.generatePublic(new X509EncodedKeySpec(encodedKey));
                        fail("Should have thrown InvalidKeySpecException");
                    } catch (InvalidKeySpecException e) {
                        // Ignore - expected exception
                    }

                    try {
                        kf.translateKey(publicKey);
                        fail("Should have thrown InvalidKeyException");
                    } catch (InvalidKeyException e) {
                        // Ignore - expected exception
                    }
                }
            }
        }
    }

    private enum InvalidComponent {NULL, ZERO, NEGATIVE}
}
