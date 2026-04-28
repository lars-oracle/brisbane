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
import java.security.Key;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.ECPoint;
import java.security.spec.ECPrivateKeySpec;
import java.security.spec.ECPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.KeyParts;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class EcKeyFactoryVectorTest {

    private final KeyPairTestData kp;
    private KeyFactory kf;

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        List<Object[]> data = new ArrayList<>();
        List<KeyPairTestData> keyPairs = TestData.get(KeyPairTestData.class, alg("EC"));
        for (KeyPairTestData kp : keyPairs) {
            data.add(new Object[]{kp.getSecParam(), kp});
        }
        return data;
    }

    public EcKeyFactoryVectorTest(String curve, KeyPairTestData kp) {
        this.kp = kp;
    }

    @Before
    public void setUp() throws Exception {
        kf = ProviderUtil.getKeyFactory("EC");
    }

    @Test
    public void generatePrivatePkcs8Spec() throws Exception {
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        checkKey(kp, privateKey);
    }

    @Test
    public void generatePublicX509Spec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        assertTrue(pubKey instanceof ECPublicKey);
        checkKey(kp, pubKey);
    }

    @Test
    public void generateEcPublicKeySpec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new ECPublicKeySpec(
                new ECPoint(new BigInteger(1, kp.getKeyParts().getPubX()),
                        new BigInteger(1, kp.getKeyParts().getPubY())),
                EcParamTestUtil.get(kp.getSecParam())));
        checkKey(kp, pubKey);
    }

    @Test
    public void generateEcPrivateKeySpec() throws Exception {
        PrivateKey privKey = kf.generatePrivate(new ECPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                EcParamTestUtil.get(kp.getSecParam())));
        checkKey(kp, privKey);
    }

    void checkKey(KeyPairTestData kp, PublicKey pubkey) {
        assertTrue(pubkey instanceof ECPublicKey);
        ECPublicKey key = (ECPublicKey) pubkey;
        assertArrayEquals(kp.getPub(), key.getEncoded());
        assertArrayEquals(kp.getKeyParts().getPubX(), key.getW().getAffineX().toByteArray());
        assertArrayEquals(kp.getKeyParts().getPubY(), key.getW().getAffineY().toByteArray());
        EcParamTestUtil.paramsEquals(EcParamTestUtil.get(kp.getSecParam()), key.getParams());
    }

    void checkKey(KeyPairTestData kp, PrivateKey privateKey) throws Exception {
        assertTrue(privateKey instanceof ECPrivateKey);
        ECPrivateKey key = (ECPrivateKey) privateKey;
        assertArrayEquals(kp.getKeyParts().getPrivValue(), key.getS().toByteArray());
        EcParamTestUtil.paramsEquals(EcParamTestUtil.get(kp.getSecParam()), key.getParams());
        if (!Arrays.equals(kp.getPriv(), key.getEncoded())) {
            // Different providers are known to output different encodings.
            // To ensure the encoding is correct, decode the encoding and
            // ensure all key parts are as expected.
            if (kp.getProvider().equals("JsafeJCE")) {
                ECPrivateKey key2 = (ECPrivateKey) kf.generatePrivate(new PKCS8EncodedKeySpec(key.getEncoded()));
                assertArrayEquals(kp.getKeyParts().getPrivValue(), key2.getS().toByteArray());
                EcParamTestUtil.paramsEquals(EcParamTestUtil.get(kp.getSecParam()), key.getParams());
            }
        }
    }

    @Test
    public void getKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // We expect getKeySpec(key, KeySpec.class) to return a X509EncodedKeySpec or ECPublicKeySpec as
        // KeySpec is assignable from both X509EncodedKeySpec and ECPublicKeySpec.
        // JipherJCE should return a ECPublicKeySpec to match the SunEC Provider.
        assertTrue(spec instanceof ECPublicKeySpec);
        checkECPublicKeySpec(kp.getKeyParts(), (ECPublicKeySpec) spec);
    }

    @Test
    public void getEncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Public key is an ECPublicKey. We expect getKeySpec(key, EncodedKeySpec.class) to
        // return a X509EncodedKeySpec because EncodedKeySpec is assignable from X509EncodedKeySpec
        assertTrue(spec instanceof X509EncodedKeySpec);
        assertArrayEquals(kp.getPub(), spec.getEncoded());
    }

    @Test
    public void getX509EncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        X509EncodedKeySpec spec = kf.getKeySpec(key, X509EncodedKeySpec.class);
        assertArrayEquals(kp.getPub(), spec.getEncoded());
    }

    @Test
    public void getECPublicKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        ECPublicKeySpec spec = kf.getKeySpec(key, ECPublicKeySpec.class);
        checkECPublicKeySpec(kp.getKeyParts(), (ECPublicKeySpec) spec);
    }

    void checkECPublicKeySpec(KeyParts keyParts, ECPublicKeySpec spec) {
        assertArrayEquals(keyParts.getPubX(), spec.getW().getAffineX().toByteArray());
        assertArrayEquals(keyParts.getPubY(), spec.getW().getAffineY().toByteArray());
    }

    @Test
    public void getKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // Private key is an ECPrivateKey. We expect getKeySpec(key, KeySpec.class) to
        // return a PKCS8EncodedKeySpec or ECPrivateKeySpec as
        // KeySpec is assignable from both PKCS8EncodedKeySpec and ECPrivateKeySpec.
        // JipherJCE should return a PKCS8EncodedKeySpec to match the SunEC Provider.
        assertTrue(spec instanceof PKCS8EncodedKeySpec);

        // We can't compare encodings since keys from other providers encode
        // differently. We'll check it by decoding and comparing keys.
        PrivateKey key2 = kf.generatePrivate(new PKCS8EncodedKeySpec(((PKCS8EncodedKeySpec) spec).getEncoded()));
        assertEquals(key, key2);
    }

    @Test
    public void getEncodedKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Private key is an ECPrivateKey. We expect getKeySpec(key, EncodedKeySpec.class) to
        // return an PKCS8EncodedKeySpec because EncodedKeySpec is assignable from PKCS8EncodedKeySpec
        assertTrue(spec instanceof PKCS8EncodedKeySpec);

        // We can't compare encodings since keys from other providers encode
        // differently. We'll check it by decoding and comparing keys.
        PrivateKey key2 = kf.generatePrivate(new PKCS8EncodedKeySpec(spec.getEncoded()));
        assertEquals(key, key2);
    }

    @Test
    public void getPKCS8EncodedKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        PKCS8EncodedKeySpec spec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);

        // We can't compare encodings since keys from other providers encode
        // differently. We'll check it by decoding and comparing keys.
        PrivateKey key2 = kf.generatePrivate(new PKCS8EncodedKeySpec(spec.getEncoded()));
        assertEquals(key, key2);
    }

    @Test
    public void getECPrivateKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        ECPrivateKeySpec spec = kf.getKeySpec(key, ECPrivateKeySpec.class);
        checkECPrivateKeySpec(kp.getKeyParts(), spec);
    }

    void checkECPrivateKeySpec(KeyParts keyParts, ECPrivateKeySpec spec) {
        assertArrayEquals(keyParts.getPrivValue(), spec.getS().toByteArray());
    }

    @Test
    public void translatePrivateKey() throws Exception {
        ECPrivateKey privKey = KeyUtil.getDummyEcPrivateKey(kp.getPriv());
        Key key = kf.translateKey(privKey);
        assertTrue(key instanceof PrivateKey);
        checkKey(kp, (PrivateKey) key);
    }

    @Test
    public void translatePublicKey() throws Exception {
        ECPublicKey pubKey = KeyUtil.getDummyEcPublicKey(kp.getPub());

        Key key = kf.translateKey(pubKey);
        assertTrue(key instanceof PublicKey);
        checkKey(kp, (PublicKey) key);
    }

    @Test
    public void translatePrivateFromEncoding() throws Exception {
        PrivateKey key = KeyUtil.getDummyPrivateKey("EC", kp.getPriv());
        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PrivateKey);
        checkKey(kp, (PrivateKey) translated);
    }
    @Test
    public void translatePublicFromEncoding() throws Exception {
        PublicKey key = KeyUtil.getDummyPublicKey("EC", kp.getPub());
        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PublicKey);
        checkKey(kp, (PublicKey) translated);
    }
}
