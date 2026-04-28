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
import java.security.PublicKey;
import java.security.interfaces.DSAPublicKey;
import java.security.spec.DSAPublicKeySpec;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

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
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class DsaKeyFactoryVectorTest {

    private final KeyPairTestData kp;
    private KeyFactory kf;

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        List<Object[]> data = new ArrayList<>();
        List<KeyPairTestData> keyPairs = TestData.get(KeyPairTestData.class, alg("DSA"));
        for (KeyPairTestData kp : keyPairs) {
            data.add(new Object[]{kp.getSecParam(), kp});
        }
        return data;
    }

    public DsaKeyFactoryVectorTest(String curve, KeyPairTestData kp) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported());
        this.kp = kp;
    }

    @Before
    public void setUp() throws Exception {
        kf = ProviderUtil.getKeyFactory("DSA");
    }

    @Test
    public void generatePublicX509Spec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        assertTrue(pubKey instanceof DSAPublicKey);
        checkKey(kp, pubKey);
    }

    @Test
    public void generateDsaPublicKeySpec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new DSAPublicKeySpec(
                new BigInteger(1, kp.getKeyParts().getPubValue()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getG())));
        checkKey(kp, pubKey);
    }

    void checkKey(KeyPairTestData kp, PublicKey pubkey) {
        assertTrue(pubkey instanceof DSAPublicKey);
        DSAPublicKey key = (DSAPublicKey) pubkey;
        assertArrayEquals(kp.getPub(), key.getEncoded());
        assertArrayEquals(kp.getKeyParts().getPubValue(), key.getY().toByteArray());
        assertArrayEquals(kp.getKeyParts().getP(), key.getParams().getP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getQ(), key.getParams().getQ().toByteArray());
        assertArrayEquals(kp.getKeyParts().getG(), key.getParams().getG().toByteArray());
    }

    @Test
    public void getKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // We expect getKeySpec(key, KeySpec.class) to return a X509EncodedKeySpec or DSAPublicKeySpec as
        // KeySpec is assignable from both X509EncodedKeySpec and X509EncodedKeySpec.
        // JipherJCE should return a DSAPublicKeySpec to match the SUN Provider.
        assertTrue(spec instanceof DSAPublicKeySpec);
        checkDSAPublicKeySpec(kp.getKeyParts(), (DSAPublicKeySpec) spec);
    }

    @Test
    public void getEncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Public key is an DSAPublicKey. We expect getKeySpec(key, EncodedKeySpec.class) to
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
    public void getDSAPublicKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        DSAPublicKeySpec spec = kf.getKeySpec(key, DSAPublicKeySpec.class);
        checkDSAPublicKeySpec(kp.getKeyParts(), spec);
    }

    void checkDSAPublicKeySpec(KeyParts keyParts, DSAPublicKeySpec spec) {
        assertArrayEquals(keyParts.getP(), spec.getP().toByteArray());
        assertArrayEquals(keyParts.getQ(), spec.getQ().toByteArray());
        assertArrayEquals(keyParts.getG(), spec.getG().toByteArray());
        assertArrayEquals(keyParts.getPubValue(), spec.getY().toByteArray());
    }

    @Test
    public void translatePublicKey() throws Exception {
        DSAPublicKey pubKey = KeyUtil.getDummyDsaPublicKey(kp.getPub());

        Key key = kf.translateKey(pubKey);
        assertTrue(key instanceof PublicKey);
        checkKey(kp, (PublicKey) key);
    }

    @Test
    public void translatePublicFromEncoding() throws Exception {
        PublicKey key = KeyUtil.getDummyPublicKey("DSA", kp.getPub());
        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PublicKey);
        checkKey(kp, (PublicKey) translated);
    }
}
