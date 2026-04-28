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
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.KeyParts;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class DhKeyFactoryVectorTest {

    private final KeyPairTestData kp;
    private KeyFactory kf;

    @Parameters(name = "{0} [{index}]")
    public static Collection<Object[]> data() throws Exception {
        List<Object[]> data = new ArrayList<>();
        List<KeyPairTestData> keyPairs = TestData.get(KeyPairTestData.class, alg("DH"));
        for (KeyPairTestData kp : keyPairs) {
            data.add(new Object[]{kp.getSecParam(), kp});
        }
        return data;
    }

    public DhKeyFactoryVectorTest(String secParam, KeyPairTestData kp) {
        Assume.assumeTrue(FipsProviderInfoUtil.isFIPS186_4TypeDomainParametersSupported() ||
                kp.getSecParam().startsWith("MODP-") || kp.getSecParam().startsWith("ffdhe-"));
        this.kp = kp;
    }

    @Before
    public void setUp() throws Exception {
        kf = ProviderUtil.getKeyFactory("DH");
    }

    @Test
    public void generatePrivatePkcs8Spec() throws Exception {
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        assertTrue(privateKey instanceof DHPrivateKey);
        checkKey(kp, privateKey);
    }

    @Test
    public void generatePublicX509Spec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        assertTrue(pubKey instanceof DHPublicKey);
        checkKey(kp, pubKey);
    }

    @Test
    public void generateDhPublicKeySpec() throws Exception {
        DHPublicKeySpec dhPublicKeySpec = new DHPublicKeySpec(
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getG()));

        PublicKey pubKey = kf.generatePublic(dhPublicKeySpec);
        checkKey(kp, pubKey);
    }

    @Test
    public void generateDhPrivateKeySpec() throws Exception {
        DHPrivateKeySpec dhPrivateKeySpec =  new DHPrivateKeySpec(
                new BigInteger(1, kp.getKeyParts().getPrivValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getG()));

        PrivateKey privKey = kf.generatePrivate(dhPrivateKeySpec);
        checkKey(kp, privKey);
    }

    void checkKey(KeyPairTestData kp, PublicKey pubkey) {
        assertTrue(pubkey instanceof DHPublicKey);
        DHPublicKey key = (DHPublicKey) pubkey;

        // DHPublicKeySpec does not support specifying parameter L when calling
        // KeyFactory.generatePublic(KeySpec).
        // As a result, the PublicKey produced by KeyFactory will not carry L, and its
        // ASN.1 encoding will omit L as well.
        // If the test vector includes L, it will be present in the test vector's ASN.1 encoding.
        // Therefore, when the test vector includes L and the key is generated as above,
        // we cannot directly compare the ASN.1 encodings.
        if ((kp.getKeyParts().getL() == key.getParams().getL())) {
            assertArrayEquals(kp.getPub(), key.getEncoded());
        }

        assertArrayEquals(kp.getKeyParts().getPubValue(), key.getY().toByteArray());
        assertArrayEquals(kp.getKeyParts().getP(), key.getParams().getP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getG(), key.getParams().getG().toByteArray());

        assertEquals("X.509", pubkey.getFormat());
    }

    void checkKey(KeyPairTestData kp, PrivateKey privateKey) throws Exception {
        assertTrue(privateKey instanceof DHPrivateKey);
        DHPrivateKey key = (DHPrivateKey) privateKey;

        // DHPrivateKeySpec does not support specifying parameter L when calling
        // KeyFactory.generatePrivate(KeySpec).
        // As a result, the PrivateKey produced by KeyFactory will not carry L, and its
        // ASN.1 encoding will omit L as well.
        // If the test vector includes L, it will be present in the test vector's ASN.1 encoding.
        // Therefore, when the test vector includes L and the key is generated as above,
        // we cannot directly compare the ASN.1 encodings.
        if ((kp.getKeyParts().getL() == key.getParams().getL())) {
            assertArrayEquals(kp.getPriv(), key.getEncoded());
        }

        assertArrayEquals(kp.getKeyParts().getPrivValue(), key.getX().toByteArray());
        assertArrayEquals(kp.getKeyParts().getP(), key.getParams().getP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getG(), key.getParams().getG().toByteArray());

        assertEquals("PKCS#8", privateKey.getFormat());
    }

    @Test
    public void getKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // We expect getKeySpec(key, KeySpec.class) to return a X509EncodedKeySpec or DHPublicKeySpec as
        // KeySpec is assignable from both X509EncodedKeySpec and DHPublicKeySpec.
        // JipherJCE should return a DHPublicKeySpec to match the SunJCE Provider.
        assertTrue(spec instanceof DHPublicKeySpec);
        checkDHPublicKeySpec(kp.getKeyParts(), (DHPublicKeySpec) spec);
    }

    @Test
    public void getEncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Public key is an DHPublicKey. We expect getKeySpec(key, EncodedKeySpec.class) to
        // return a X509EncodedKeySpec because EncodedKeySpec is assignable from X509EncodedKeySpec
        assertTrue(spec instanceof X509EncodedKeySpec);

        if (kp.getProvider().startsWith("S")) {
            assertArrayEquals(kp.getPub(), spec.getEncoded());
        } else {
            // We can't compare encodings since keys from other providers encode
            // differently. We'll check it by decoding and comparing keys.
            PublicKey key2 = kf.generatePublic(new X509EncodedKeySpec(spec.getEncoded()));
            assertEquals(key, key2);
        }
    }

    @Test
    public void getX509EncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        X509EncodedKeySpec spec = kf.getKeySpec(key, X509EncodedKeySpec.class);

        if (kp.getProvider().startsWith("S")) {
            assertArrayEquals(kp.getPub(), spec.getEncoded());
        } else {
            // We can't compare encodings since keys from other providers encode
            // differently. We'll check it by decoding and comparing keys.
            PublicKey key2 = kf.generatePublic(new X509EncodedKeySpec(spec.getEncoded()));
            assertEquals(key, key2);
        }
    }

    @Test
    public void getDHPublicKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        DHPublicKeySpec spec = kf.getKeySpec(key, DHPublicKeySpec.class);
        checkDHPublicKeySpec(kp.getKeyParts(), spec);
    }

    void checkDHPublicKeySpec(KeyParts keyParts, DHPublicKeySpec spec) {
        assertArrayEquals(keyParts.getP(), spec.getP().toByteArray());
        assertArrayEquals(keyParts.getG(), spec.getG().toByteArray());
        assertArrayEquals(keyParts.getPubValue(), spec.getY().toByteArray());
    }

    @Test
    public void getKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // Private key is an ECPrivateKey. We expect getKeySpec(key, KeySpec.class) to
        // return a PKCS8EncodedKeySpec or DHPrivateKeySpec as
        // KeySpec is assignable from both PKCS8EncodedKeySpec and DHPrivateKeySpec.
        // JipherJCE should return a DHPrivateKeySpec to match the SunJCE Provider.
        assertTrue(spec instanceof DHPrivateKeySpec);
        checkDHPrivateKeySpec(kp.getKeyParts(), (DHPrivateKeySpec) spec);
    }

    @Test
    public void getEncodedKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Private key is an DHPrivateKey. We expect getKeySpec(key, EncodedKeySpec.class) to
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
    public void getDHPrivateKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        DHPrivateKeySpec spec = kf.getKeySpec(key, DHPrivateKeySpec.class);
        checkDHPrivateKeySpec(kp.getKeyParts(), spec);
    }

    void checkDHPrivateKeySpec(KeyParts keyParts, DHPrivateKeySpec spec) {
        assertArrayEquals(keyParts.getP(), spec.getP().toByteArray());
        assertArrayEquals(keyParts.getG(), spec.getG().toByteArray());
        assertArrayEquals(keyParts.getPrivValue(), spec.getX().toByteArray());
    }

    @Test
    public void getKeySpecPrivate() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        DHPrivateKeySpec spec = kf.getKeySpec(key, DHPrivateKeySpec.class);
        assertArrayEquals(kp.getKeyParts().getP(), spec.getP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getG(), spec.getG().toByteArray());
        assertArrayEquals(kp.getKeyParts().getPrivValue(), spec.getX().toByteArray());
    }

    @Test
    public void getKeySpecPrivateEncoded() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        PKCS8EncodedKeySpec spec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);

        // We can't compare encodings since keys from other providers encode differently.
        // We'll check it by decoding and comparing keys.
        PrivateKey key2 = kf.generatePrivate(new PKCS8EncodedKeySpec(spec.getEncoded()));
        assertEquals(key, key2);
    }

    @Test
    public void translatePrivateKey() throws Exception {
        DHPrivateKey privKey = KeyUtil.getDummyDhPrivateKey(kp.getPriv());
        Key key = kf.translateKey(privKey);
        assertTrue(key instanceof PrivateKey);
        checkKey(kp, (PrivateKey) key);
    }

    @Test
    public void translatePublicKey() throws Exception {
        DHPublicKey pubKey = KeyUtil.getDummyDhPublicKey(kp.getPub());

        Key key = kf.translateKey(pubKey);
        assertTrue(key instanceof PublicKey);
        checkKey(kp, (PublicKey) key);
    }

    @Test
    public void translatePrivateFromEncoding() throws Exception {
        PrivateKey key = KeyUtil.getDummyPrivateKey("DH", kp.getPriv());
        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PrivateKey);
        checkKey(kp, (PrivateKey) translated);
    }
    @Test
    public void translatePublicFromEncoding() throws Exception {
        PublicKey key = KeyUtil.getDummyPublicKey("DH", kp.getPub());
        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PublicKey);
        checkKey(kp, (PublicKey) translated);
    }
}
