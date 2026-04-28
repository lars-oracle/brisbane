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

package com.oracle.test.integration.keyagree;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyFactory;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.EllipticCurve;
import java.security.spec.InvalidKeySpecException;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.crypto.KeyAgreement;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.ShortBufferException;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;
import javax.crypto.spec.DESedeKeySpec;
import javax.crypto.spec.DHParameterSpec;
import javax.crypto.spec.DHPublicKeySpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyAgreeTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static com.oracle.test.integration.keyfactory.EcParamTestUtil.P224_PARAM_SPEC;
import static com.oracle.test.integration.keyfactory.EcParamTestUtil.P256_PARAM_SPEC;
import static com.oracle.test.integration.keyfactory.EcParamTestUtil.paramsEquals;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class KeyAgreeApiTest {
    static List<String> approvedParams = Arrays.asList(new String[]{"secp224r1", "secp256r1", "secp384r1", "secp521r1", "ffdhe2048", "ffdhe3072", "ffdhe4096", "MODP-2048", "MODP-3072", "MODP-4096"});

    private final String alg;
    private final KeyAgreement agree;
    private KeyAgreeTestVector tv;
    PrivateKey priv;
    PublicKey pub;
    AlgorithmParameterSpec keyParams;

    @Parameterized.Parameters(name = "{0}-{1}")
    public static Collection<Object[]> params() throws Exception {
        return Arrays.asList(
                new Object[]{"ECDH", false},
                new Object[]{"ECDH", true},
                new Object[]{"DH", false},
                new Object[]{"DH", true}
        );
    }

    public KeyAgreeApiTest(String alg, boolean secretHasLeadingZeroByte) throws Exception {
        this.alg = alg;

        // Find a test vector, for the specified algorithm, that uses an approved ECC Curve or FFC Safe-prime Group,
        // and that has a shared secret that has or has not a leading zero byte as requested.
        this.tv = null;
        for (KeyAgreeTestVector tv: TestData.get(KeyAgreeTestVector.class, alg(alg))) {
            if (!approvedParams.contains(TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId())).getSecParam())) {
                continue;
            }
            if ((tv.getSecret()[0] == 0) == secretHasLeadingZeroByte) {
                this.tv = tv;
                break;
            }
        }
        assertNotNull(this.tv);

        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        priv = KeyUtil.loadPrivate(kp.getAlg(), kp.getPriv());
        pub = KeyUtil.loadPublic(kp.getAlg(), tv.getPeerPub());

        agree = ProviderUtil.getKeyAgreement(alg);
        if (alg.equals("ECDH")) {
            this.keyParams = ((ECPrivateKey) priv).getParams();
        } else if (alg.equals("DH")) {
            this.keyParams = ((DHPrivateKey) priv).getParams();
        } else {
            throw new Error("Unsupported alg: " + alg);
        }
    }

    @Test
    public void generateSecret() throws Exception {
        agree.init(priv);
        agree.doPhase(pub, true);
        assertArrayEquals(tv.getSecret(), agree.generateSecret());
    }

    @Test
    public void generateSecretBuffer() throws Exception {
        agree.init(priv, null, null);
        agree.doPhase(pub, true);
        byte[] bb = new byte[tv.getSecret().length + 10];
        agree.generateSecret(bb, 10);
        assertArrayEquals(tv.getSecret(), Arrays.copyOfRange(bb, 10, bb.length));
    }

    private SecretKey getSecretKey(byte[] keyMaterial, String algorithm) throws NoSuchAlgorithmException, NoSuchProviderException, InvalidKeyException, InvalidKeySpecException {
        if (algorithm.equalsIgnoreCase("AES")) {
            int length = (keyMaterial.length >= 32) ? 32 : (keyMaterial.length >= 24) ? 24: 16;
            return new SecretKeySpec(keyMaterial, 0, length, algorithm);
        } else if (algorithm.equalsIgnoreCase("DESede")) {
            SecretKeyFactory secretKeyFactory = SecretKeyFactory.getInstance(algorithm, "SunJCE");
            return secretKeyFactory.generateSecret(new DESedeKeySpec(keyMaterial));
        } else if  (algorithm.equalsIgnoreCase("TlsPremasterSecret")) {
            if (this.alg.equals("DH")) {
                return new SecretKeySpec(TestUtil.trimLeadingZeros(keyMaterial), algorithm);
            } else {
                return new SecretKeySpec(keyMaterial, algorithm);
            }
        } else {
            throw new NoSuchAlgorithmException("Unsupported secret key algorithm: " + alg);
        }
    }

    private void generateSecretKey(String algorithm) throws Exception {
        agree.init(priv);
        agree.doPhase(pub, true);
        SecretKey secretKey = agree.generateSecret(algorithm);
        assertNotNull(secretKey);
        assertEquals(algorithm, secretKey.getAlgorithm());
        assertEquals(getSecretKey(tv.getSecret(), algorithm), secretKey);
    }

    @Test
    public void generateAesSecretKey() throws Exception {
        assertTrue(tv.getSecret().length >= 16);
        generateSecretKey("AES");
    }

    @Test
    public void generateDesEdeSecretKey() throws Exception {
        assertTrue(tv.getSecret().length >= 24);
        generateSecretKey("DESede");
    }

    @Test
    public void generateTlsPremasterSecrettKey() throws Exception {
        generateSecretKey("TlsPremasterSecret");
    }

    // Tests that once init has been called the keyagree object
    // is independent of the key passed to init
    // (which may be destroyed by the application)
    @Test
    public void generateSecretFromDestroyedKey() throws Exception {
        PrivateKey key = KeyUtil.duplicate(priv);
        agree.init(key);
        key.destroy();
        agree.doPhase(pub, true);
        assertArrayEquals(tv.getSecret(), agree.generateSecret());
    }

    // Tests that an implicit (re)init following a key destroy works
    @Test
    public void generateAnotherSecretFromDestroyedKey() throws Exception {
        PrivateKey key = KeyUtil.duplicate(priv);
        agree.init(key);
        agree.doPhase(pub, true);

        key.destroy();
        agree.doPhase(pub, true);
        assertArrayEquals(tv.getSecret(), agree.generateSecret());
    }

    @Test(expected = IllegalStateException.class)
    public void doPhaseFalse() throws Exception {
        agree.init(priv);
        agree.doPhase(pub, false);
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseNotPublicKey() throws Exception {
        agree.init(priv);
        agree.doPhase(priv, true);
    }

    @Test(expected = InvalidKeyException.class)
    public void initPublicKey() throws Exception {
        agree.init(pub);
    }

    @Test
    public void initOtherProvCorrectKey() throws Exception {
        agree.init(KeyUtil.getDummyPrivateKey(priv.getEncoded(), priv.getClass()));
    }

    @Test
    public void doPhaseOtherProvCorrectKey() throws Exception {
        agree.init(priv);
        agree.doPhase(KeyUtil.getDummyPublicKey(tv.getPeerPub(), pub.getClass()), true);
        assertArrayEquals(tv.getSecret(), agree.generateSecret());
    }

    @Test(expected = InvalidKeyException.class)
    public void initInvalidPrivateKey() throws Exception {
        agree.init(KeyUtil.getDummyPrivateKey(this.priv.getAlgorithm(), pub.getEncoded()));
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseInvalidPublicKey() throws Exception {
        agree.init(priv);
        agree.doPhase(KeyUtil.getDummyPublicKey(this.priv.getAlgorithm(), tv.getSecret()), true);
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseInvalidDHPublicKeyYEquals1() throws Exception {
        Assume.assumeTrue(pub instanceof DHPublicKey);
        agree.init(priv);
        DHParameterSpec paramSpec = ((DHPublicKey) pub).getParams();
        DHPublicKeySpec keySpec = new DHPublicKeySpec(BigInteger.ONE, paramSpec.getP(), paramSpec.getG());
        agree.doPhase(KeyFactory.getInstance(alg).generatePublic(keySpec), true);
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseInvalidDHPublicKeyYEqualsPminus1() throws Exception {
        Assume.assumeTrue(pub instanceof DHPublicKey);
        agree.init(priv);
        DHParameterSpec paramSpec = ((DHPublicKey) pub).getParams();
        DHPublicKeySpec keySpec = new DHPublicKeySpec(paramSpec.getP().add(BigInteger.valueOf(-1)), paramSpec.getP(), paramSpec.getG());
        agree.doPhase(KeyFactory.getInstance(alg).generatePublic(keySpec), true);
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseInvalidDHPublicKeyDifferentDomainParameters() throws Exception {
        Assume.assumeTrue(pub instanceof DHPublicKey);
        agree.init(priv);
        DHParameterSpec paramSpec = ((DHPublicKey) pub).getParams();
        String differentDomainName = paramSpec.getP().bitLength() == 2048 ? "ffdhe4096": "ffdhe2048";
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("DH").secParam(differentDomainName));
        agree.doPhase(KeyUtil.loadPublic(kp.getAlg(), kp.getPub()), true);
    }

    @Test(expected = InvalidKeyException.class)
    public void doPhaseInvalidECDHPublicKeyDifferentCurve() throws Exception {
        Assume.assumeTrue(pub instanceof ECPublicKey);
        agree.init(priv);
        int test = ((ECPublicKey) pub).getParams().getCurve().getField().getFieldSize();
        EllipticCurve curve = ((ECPublicKey) pub).getParams().getCurve();
        String differentCurveName = curve.getField().getFieldSize() == 256 ? "secp384r1" : "secp256r1";
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, alg("EC").secParam(differentCurveName));
        agree.doPhase(KeyUtil.loadPublic(kp.getAlg(), kp.getPub()), true);
    }

    @Test(expected = IllegalStateException.class)
    public void doPhaseBeforeInit() throws Exception {
        agree.doPhase(pub, true);
    }

    @Test(expected = IllegalStateException.class)
    public void generateSecretNoInit1() throws Exception {
        agree.generateSecret();
    }

    @Test(expected = IllegalStateException.class)
    public void generateSecretNoInit2() throws Exception {
        byte[] bb = new byte[100];
        agree.generateSecret(bb, 0);
    }

    @Test(expected = IllegalStateException.class)
    public void generateSecretWithoutDoPhase() throws Exception {
        agree.init(priv);
        agree.generateSecret();
    }

    @Test(expected = ShortBufferException.class)
    public void generateSecretBufferTooSmall() throws Exception {
        agree.init(priv);
        agree.doPhase(pub, true);

        byte[] out = new byte[tv.getSecret().length];
        agree.generateSecret(out, 1);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidParameterSpec() throws Exception {
        agree.init(priv, new DSAParameterSpec(BigInteger.valueOf(777), BigInteger.valueOf(777), BigInteger.valueOf(777)));
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initParameterSpecMismatch() throws Exception {
        AlgorithmParameterSpec spec;
        if (this.alg.equals("ECDH")) {
            spec = paramsEquals(((ECPrivateKey) priv).getParams(),
                    P224_PARAM_SPEC) ? P256_PARAM_SPEC : P224_PARAM_SPEC;
        } else {
            DHParameterSpec thisSpec = (DHParameterSpec) this.keyParams;
            spec = new DHParameterSpec(thisSpec.getP(), thisSpec.getG().add(BigInteger.ONE));
        }
        agree.init(priv, spec);
    }

    @Test
    public void initParameterSpec() throws Exception {
        agree.init(priv, this.keyParams);
        agree.doPhase(pub, true);
        assertArrayEquals(tv.getSecret(), agree.generateSecret());
    }
}
