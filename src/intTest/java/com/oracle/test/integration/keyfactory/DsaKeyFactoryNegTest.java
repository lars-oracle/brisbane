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
import java.security.spec.DSAPrivateKeySpec;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.fail;

public class DsaKeyFactoryNegTest {
    KeyPairTestData kp;
    KeyFactory kf;

    public DsaKeyFactoryNegTest() {
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported());
    }

    @Before
    public void setUp() throws Exception {
        kp = TestData.getFirst(KeyPairTestData.class, alg("DSA").secParam("2048-224"));
        kf = ProviderUtil.getKeyFactory("DSA");
    }

    @Test (expected = UnsupportedOperationException.class)
    public void generatePrivatePkcs8Spec() throws Exception {
        kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
    }

    @Test (expected = UnsupportedOperationException.class)
    public void generateDsaPrivateKeySpec() throws Exception {
        kf.generatePrivate(new DSAPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getG())));
    }

    @Test (expected = UnsupportedOperationException.class)
    public void translatePrivateFromEncoding() throws Exception {
        PrivateKey key = KeyUtil.getDummyPrivateKey("DSA", kp.getPriv());
        kf.translateKey(key);
    }

    @Test (expected = UnsupportedOperationException.class)
    public void translatePrivateKey() throws Exception {
        DSAPrivateKey privKey = KeyUtil.getDummyDsaPrivateKey(kp.getPriv());
        kf.translateKey(privKey);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubNull() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, null);
    }

    @Test(expected= InvalidKeySpecException.class)
    public void getKeySpecPubInvalid() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, DSAPrivateKeySpec.class);
    }

    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecNotECKey() throws Exception {
        X509EncodedKeySpec spec = kf.getKeySpec(new SecretKeySpec(new byte[16], "AES"), X509EncodedKeySpec.class);
    }

    @Test(expected = InvalidKeyException.class)
    public void translateNotAsymmetric() throws Exception {
        kf.translateKey(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected= InvalidKeySpecException.class)
    public void generatePublicBadSpec() throws Exception {
        kf.generatePublic(new SecretKeySpec(new byte[16], "AES"));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicNullParameters() throws Exception {
        kf.generatePublic(new DSAPublicKeySpec(
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                null));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePublicBadParameterValue() throws Exception {
        kf.generatePublic(new DSAPublicKeySpec(
                BigInteger.ZERO,
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getG())));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubKeyFailsToTranslate() throws Exception {
        PublicKey key = KeyUtil.getDummyDsaPublicKey(new byte[14]);
        kf.getKeySpec(key, DSAPublicKeySpec.class);
    }

    @Test
    public void invalidPublicKeyComponents() throws Exception {
        KeyFactory sunKeyFactory = KeyFactory.getInstance("DSA", "SUN");
        BigInteger[] valid =  new BigInteger[] {
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getG())
        };

        for (InvalidComponent invalid : InvalidComponent.values()) {
            for (int i = 0; i < valid.length; i++) {
                BigInteger[] bi = valid.clone();
                bi[i] = invalid == InvalidComponent.NULL ? null : invalid == InvalidComponent.ZERO ? BigInteger.ZERO : bi[i].negate();
                DSAPublicKeySpec keySpec = new DSAPublicKeySpec(bi[0], bi[1], bi[2], bi[3]);

                try {
                    kf.generatePublic(keySpec);
                    fail("Should have thrown InvalidKeySpecException");
                } catch (InvalidKeySpecException e) {
                    // Ignore - expected exception
                }

                // The SUN provider will not encode null parameters
                if (invalid != InvalidComponent.NULL) {
                    PublicKey publicKey = sunKeyFactory.generatePublic(keySpec);
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
