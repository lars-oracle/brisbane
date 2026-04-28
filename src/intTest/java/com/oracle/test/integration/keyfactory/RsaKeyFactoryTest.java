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
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.EncodedKeySpec;
import java.security.spec.KeySpec;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.security.spec.RSAPublicKeySpec;
import java.security.spec.X509EncodedKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.KeyParts;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertTrue;

public class RsaKeyFactoryTest {

    KeyPairTestData kp;
    KeyFactory kf;

    @Before
    public void setUp() throws Exception {

        kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("RSA"));

//        kp = TestData.getKeyPairs().getFirst("RSA", null);
        kf = ProviderUtil.getKeyFactory("RSA");
    }

    @Test
    public void generatePrivatePkcs8Spec() throws Exception {
        PrivateKey privateKey = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        checkKey(kp, privateKey);
    }

    @Test
    public void generatePublicX509Spec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        assertTrue(pubKey instanceof RSAPublicKey);
        checkKey(kp, pubKey);
    }

    @Test
    public void generateRsaPublicKeySpec() throws Exception {
        PublicKey pubKey = kf.generatePublic(new RSAPublicKeySpec(new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE())));
        checkKey(kp, pubKey);
    }

    @Test
    public void generateRsaPrivateCrtKeySpec() throws Exception {
        PrivateKey privKey = kf.generatePrivate(new RSAPrivateCrtKeySpec(
                new BigInteger(1, kp.getKeyParts().getN()),
                new BigInteger(1, kp.getKeyParts().getE()),
                new BigInteger(1, kp.getKeyParts().getD()),
                new BigInteger(1, kp.getKeyParts().getP()),
                new BigInteger(1, kp.getKeyParts().getQ()),
                new BigInteger(1, kp.getKeyParts().getExpP()),
                new BigInteger(1, kp.getKeyParts().getExpQ()),
                new BigInteger(1, kp.getKeyParts().getCrtCoeff())));
        checkKey(kp, privKey);
    }

    void checkKey(KeyPairTestData kp, PublicKey pubkey) {
        assertTrue(pubkey instanceof RSAPublicKey);
        RSAPublicKey key = (RSAPublicKey) pubkey;
        assertArrayEquals(kp.getPub(), key.getEncoded());
        assertArrayEquals(kp.getKeyParts().getN(), key.getModulus().toByteArray());
        assertArrayEquals(kp.getKeyParts().getE(), key.getPublicExponent().toByteArray());
    }

    void checkKey(KeyPairTestData kp, PrivateKey privateKey) {
        assertTrue(privateKey instanceof RSAPrivateCrtKey);
        RSAPrivateCrtKey key = (RSAPrivateCrtKey) privateKey;
        assertArrayEquals(kp.getPriv(), key.getEncoded());
        assertArrayEquals(kp.getKeyParts().getN(), key.getModulus().toByteArray());
        assertArrayEquals(kp.getKeyParts().getE(), key.getPublicExponent().toByteArray());
        assertArrayEquals(kp.getKeyParts().getD(), key.getPrivateExponent().toByteArray());
        assertArrayEquals(kp.getKeyParts().getP(), key.getPrimeP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getQ(), key.getPrimeQ().toByteArray());
        assertArrayEquals(kp.getKeyParts().getExpP(), key.getPrimeExponentP().toByteArray());
        assertArrayEquals(kp.getKeyParts().getExpQ(), key.getPrimeExponentQ().toByteArray());
        assertArrayEquals(kp.getKeyParts().getCrtCoeff(), key.getCrtCoefficient().toByteArray());
    }

    @Test
    public void getKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // We expect getKeySpec(key, KeySpec.class) to return a X509EncodedKeySpec or RSAPublicKeySpec as
        // KeySpec is assignable from both X509EncodedKeySpec and RSAPublicKeySpec.
        // JipherJCE should return a RSAPublicKeySpec to match the SunRsaSign Provider.
        assertTrue(spec instanceof RSAPublicKeySpec);
        checkRSAPublicKeySpec(kp.getKeyParts(), (RSAPublicKeySpec) spec);
    }

    @Test
    public void getEncodedKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Public key is an RSAPublicKey. We expect getKeySpec(key, EncodedKeySpec.class) to
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
    public void getRSAPublicKeySpecFromPublicKey() throws Exception {
        PublicKey key = kf.generatePublic(new X509EncodedKeySpec(kp.getPub()));
        RSAPublicKeySpec spec = kf.getKeySpec(key, RSAPublicKeySpec.class);
        assertArrayEquals(kp.getKeyParts().getN(), spec.getModulus().toByteArray());
        assertArrayEquals(kp.getKeyParts().getE(), spec.getPublicExponent().toByteArray());
    }

    void checkRSAPublicKeySpec(KeyParts keyParts, RSAPublicKeySpec spec) {
        assertArrayEquals(keyParts.getN(), spec.getModulus().toByteArray());
        assertArrayEquals(keyParts.getE(), spec.getPublicExponent().toByteArray());
    }

    @Test
    public void getKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        KeySpec spec = kf.getKeySpec(key, KeySpec.class);
        // Private key is an RSAPrivateCrtKey. We expect getKeySpec(key, KeySpec.class) to
        // return a PKCS8EncodedKeySpec or RSAPrivateCrtKeySpec as
        // KeySpec is assignable from both PKCS8EncodedKeySpec and RSAPrivateCrtKeySpec.
        // JipherJCE should return a PKCS8EncodedKeySpec to match the SunRsaSign Provider.
        assertTrue(spec instanceof PKCS8EncodedKeySpec);
        assertArrayEquals(kp.getPriv(), ((PKCS8EncodedKeySpec) spec).getEncoded());
    }

    @Test
    public void getEncodedKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        EncodedKeySpec spec = kf.getKeySpec(key, EncodedKeySpec.class);
        // Private key is an RSAPrivateCrtKey. We expect getKeySpec(key, EncodedKeySpec.class) to
        // return an PKCS8EncodedKeySpec because EncodedKeySpec is assignable from PKCS8EncodedKeySpec
        assertTrue(spec instanceof PKCS8EncodedKeySpec);
        assertArrayEquals(kp.getPriv(), spec.getEncoded());
    }

    @Test
    public void getPKCS8EncodedKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        PKCS8EncodedKeySpec spec = kf.getKeySpec(key, PKCS8EncodedKeySpec.class);
        assertArrayEquals(kp.getPriv(), spec.getEncoded());
    }

    @Test
    public void getRSAPrivateKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        RSAPrivateKeySpec spec = kf.getKeySpec(key, RSAPrivateKeySpec.class);
        // Private key is an RSAPrivateCrtKey. We expect getKeySpec(key, RSAPrivateKeySpec.class) to
        // return an RSAPrivateCrtKeySpec because the private key has CRT parts
        // and RSAPrivateKeySpec is assignable from RSAPrivateCrtKeySpec
        assertTrue(spec instanceof RSAPrivateCrtKeySpec);
        checkRSAPrivateCrtKeySpec(kp.getKeyParts(), (RSAPrivateCrtKeySpec) spec);
    }

    @Test
    public void getRSAPrivateCrtKeySpecFromPrivateKey() throws Exception {
        PrivateKey key = kf.generatePrivate(new PKCS8EncodedKeySpec(kp.getPriv()));
        RSAPrivateCrtKeySpec spec = kf.getKeySpec(key, RSAPrivateCrtKeySpec.class);
        checkRSAPrivateCrtKeySpec(kp.getKeyParts(), spec);
    }

    void checkRSAPrivateCrtKeySpec(KeyParts keyParts, RSAPrivateCrtKeySpec spec) {
        assertArrayEquals(keyParts.getN(), spec.getModulus().toByteArray());
        assertArrayEquals(keyParts.getE(), spec.getPublicExponent().toByteArray());
        assertArrayEquals(keyParts.getD(), spec.getPrivateExponent().toByteArray());
        assertArrayEquals(keyParts.getP(), spec.getPrimeP().toByteArray());
        assertArrayEquals(keyParts.getQ(), spec.getPrimeQ().toByteArray());
        assertArrayEquals(keyParts.getExpP(), spec.getPrimeExponentP().toByteArray());
        assertArrayEquals(keyParts.getExpQ(), spec.getPrimeExponentQ().toByteArray());
        assertArrayEquals(keyParts.getCrtCoeff(), spec.getCrtCoefficient().toByteArray());
    }

    @Test
    public void translatePrivateKey() throws Exception {
        RSAPrivateKey privKey = KeyUtil.getDummyRsaPrivateKey(kp.getPriv());

        Key key = kf.translateKey(privKey);
        assertTrue(key instanceof PrivateKey);
        checkKey(kp, (PrivateKey) key);
    }

    @Test
    public void translatePublicKey() throws Exception {
        RSAPublicKey pubKey = KeyUtil.getDummyRsaPublicKey(kp.getPub());

        Key key = kf.translateKey(pubKey);
        assertTrue(key instanceof PublicKey);
        checkKey(kp, (PublicKey) key);
    }

    @Test
    public void translatePrivateFromEncoding() throws Exception {
        PrivateKey key = KeyUtil.getDummyPrivateKey("RSA", kp.getPriv());

        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PrivateKey);
        checkKey(kp, (PrivateKey) translated);
    }
    @Test
    public void translatePublicFromEncoding() throws Exception {
        PublicKey key = KeyUtil.getDummyPublicKey("RSA", kp.getPub());

        Key translated = kf.translateKey(key);
        assertTrue(translated instanceof PublicKey);
        checkKey(kp, (PublicKey) translated);
    }
}
