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
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
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

public class EcKeyFactoryNegTest {
    KeyPairTestData kp;
    KeyFactory kf;

    @Before
    public void setUp() throws Exception {
        kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam("secp256r1"));
        kf = ProviderUtil.getKeyFactory("EC");
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubNull() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, null);
    }

    @Test(expected= InvalidKeySpecException.class)
    public void getKeySpecPubInvalid() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        kf.getKeySpec(key, ECPrivateKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPrivNull() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, null);
    }

    @Test(expected=InvalidKeySpecException.class)
    public void getKeySpecPrivInvalid() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        kf.getKeySpec(key, ECPublicKeySpec.class);
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
    public void translateNotEC() throws Exception {
        DSAPrivateKey dsaPriv = KeyUtil.getDummyDsaPrivateKey(new byte[0]);

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
    public void generatePublicUnsupportedEcParameters() throws Exception {
        kf.generatePublic(new ECPublicKeySpec(
                new ECPoint(new BigInteger(1, kp.getKeyParts().getPubX()),
                        new BigInteger(1, kp.getKeyParts().getPubY())),
                EcParamTestUtil.getUnsupported()));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void generatePrivateUnsupportedEcParameters() throws Exception {
        kf.generatePrivate(new ECPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                EcParamTestUtil.getUnsupported()));
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPubKeyFailsToTranslate() throws Exception {
        PublicKey key = KeyUtil.getDummyEcPublicKey(new byte[14]);
        kf.getKeySpec(key, ECPublicKeySpec.class);
    }

    @Test(expected = InvalidKeySpecException.class)
    public void getKeySpecPrivateKeyFailsToTranslate() throws Exception {
        PrivateKey key = KeyUtil.getDummyEcPrivateKey(new byte[14]);
        kf.getKeySpec(key, ECPrivateKeySpec.class);
    }

    @Test
    public void invalidPrivateKeyComponents() throws Exception {
        KeyFactory sunEcKeyFactory = KeyFactory.getInstance("EC", "SunEC");
        BigInteger privKey =  new BigInteger(1, kp.getKeyParts().getPrivValue());

        for (InvalidComponent invalid : InvalidComponent.values()) {
            BigInteger bi = invalid == InvalidComponent.ZERO ? BigInteger.ZERO : privKey.negate();
            ECPrivateKeySpec keySpec = new ECPrivateKeySpec(bi, EcParamTestUtil.get(kp.getSecParam()));

            try {
                kf.generatePrivate(keySpec);
                fail("Should have thrown InvalidKeySpecException");
            } catch (InvalidKeySpecException e) {
                // Ignore - expected exception
            }

            // RFC-5915 section 3 defines privateKey to be an UNSIGNED integer of ceiling (log2(n)/8) octets
            // (where n is the order of the curve). Hence, it is not possible to asn.1 decode a negative private key
            // value.
            if (invalid != InvalidComponent.NEGATIVE) {
                PrivateKey privateKey = sunEcKeyFactory.generatePrivate(keySpec);
                byte[] encodedKey = privateKey.getEncoded();
                try {
                    kf.generatePublic(new X509EncodedKeySpec(encodedKey));
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

    private enum InvalidComponent {
        // An ECPrivateKeySpec does not support null parameters.
        ZERO,
        NEGATIVE
    }
}
