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

package com.oracle.test.integration.asymciph;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.Key;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static com.oracle.test.integration.asymciph.AsymCipherInitTest.InitVariant.INIT_KEY_PARAMSPEC_RANDOM;
import static com.oracle.test.integration.asymciph.AsymCipherInitTest.InitVariant.INIT_KEY_PARAMS_RANDOM;
import static com.oracle.test.integration.asymciph.AsymCipherInitTest.InitVariant.INIT_KEY_RANDOM;
import static javax.crypto.Cipher.DECRYPT_MODE;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import static org.junit.jupiter.api.Assertions.assertArrayEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AsymCipherInitTest {

    enum InitVariant {
        INIT_KEY_RANDOM,
        INIT_KEY_PARAMSPEC_RANDOM,
        INIT_KEY_PARAMS_RANDOM,
    }

    public AsymCipherInitTest() {}

    static AlgorithmParameters getOaepParameters(OAEPParameterSpec spec) {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("OAEP");
            ap.init(spec);
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }
    static AlgorithmParameters getOtherParameters() {
        try {
            AlgorithmParameters ap = AlgorithmParameters.getInstance("AES");
            ap.init(new IvParameterSpec(new byte[16]));
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }

    private static Stream<Arguments> createInitParameters() throws Exception {
        PublicKey pub = KeyUtil.loadPublic("RSA", TestData.getFirst(KeyPairTestData.class, alg("RSA").secParam("2048")).getPub());
        PrivateKey priv = KeyUtil.loadPrivate("RSA", TestData.getFirst(KeyPairTestData.class, alg("RSA").secParam("2048")).getPriv());

        return Stream.of(
                Arguments.of("RSA-OAEP:NEG:Key is SecretKey:encrypt", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, new SecretKeySpec(new byte[16], "RSA"), false,
                        null, InvalidKeyException.class),
                Arguments.of("RSA-OAEP:NEG:Encrypt with PrivateKey", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, ENCRYPT_MODE, priv, false, null, InvalidKeyException.class),
                Arguments.of("RSA-OAEP:NEG:Decrypt with PublicKey", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, DECRYPT_MODE, pub, false, null, InvalidKeyException.class),
                Arguments.of("RSA-OAEP:NEG:Encrypt not RSA public key", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, ENCRYPT_MODE, KeyUtil.getDummyPublicKey("RSA", priv.getEncoded()), false,
                        null, InvalidKeyException.class),
                Arguments.of("RSA-OAEP:NEG:Decrypt not RSA priv key", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, DECRYPT_MODE, KeyUtil.getDummyPrivateKey("RSA", pub.getEncoded()), false,
                        null, InvalidKeyException.class),
                Arguments.of("RSA-OAEP:NEG:Not OAEPParameterSpec", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(17)),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Bad digest", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("MD5", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Bad MGF Alg", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-256", "MGF34", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Null MGF Spec", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-256", "MGF1", null, PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Bad MGF Spec", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-256", "MGF1", new RSAKeyGenParameterSpec(1024,null), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Invalid MGF-1 digest", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("MD5"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:Bad PSource", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), new PSource("PSpecified") {}),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP:NEG:AlgorithmParameters.OAEP(DEFAULT)",  "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null,  false, getOtherParameters(),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP-SHA1:NEG:Digest Alg incorrect", "RSA/ECB/OAEPWithSHA1andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP-SHA-224:NEG:Digest Alg incorrect", "RSA/ECB/OAEPWithSHA-224andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP-SHA-256:NEG:Digest Alg incorrect", "RSA/ECB/OAEPWithSHA-256andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP-SHA-384:NEG:Digest Alg incorrect", "RSA/ECB/OAEPWithSHA-384andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("RSA-OAEP-SHA-512:NEG:Digest Alg incorrect", "RSA/ECB/OAEPWithSHA-512andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT),
                        InvalidAlgorithmParameterException.class),

                // Positive cases.
                Arguments.of("RSA-OAEP:OAEPParameterSpec.LEGACY_DEFAULT", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false,
                        new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP(LEGACY_DEFAULT)", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP-SHA-1", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-1", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP-SHA-224", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP-SHA-256", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP-SHA-384", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-384", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:AlgorithmParameters.OAEP-SHA-512", "RSA/ECB/OAEPPadding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-512", "MGF1", new MGF1ParameterSpec("SHA-1"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP-SHA1:OAEPParameterSpec.LEGACY_DEFAULT", "RSA/ECB/OAEPWithSHA1andMGF1Padding",
                        INIT_KEY_PARAMSPEC_RANDOM, ENCRYPT_MODE, null, false, new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT), null),
                Arguments.of("RSA-OAEP-SHA1:AlgorithmParameters.OAEP(LEGACY_DEFAULT)", "RSA/ECB/OAEPWithSHA1andMGF1Padding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false, getOaepParameters(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP-SHA-256:AlgorithmParameters.OAEP", "RSA/ECB/OAEPWithSHA-256andMGF1Padding",
                        INIT_KEY_PARAMS_RANDOM, ENCRYPT_MODE, null, false,
                        getOaepParameters(new OAEPParameterSpec("SHA-256", "MGF1", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT)),
                        null),
                Arguments.of("RSA-OAEP:Encrypt keyFromOtherProvider", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, ENCRYPT_MODE, null, true, null, null),
                Arguments.of("RSA-OAEP:Decrypt keyFromOtherProvider", "RSA/ECB/OAEPPadding",
                        INIT_KEY_RANDOM, DECRYPT_MODE, null, true, null, null)
        );
    }

    @ParameterizedTest(name = "{0}({index})")
    @MethodSource("createInitParameters")
    public void initTest(String description, String alg, InitVariant initMethod, int mode, Key initKey, boolean otherProvider, Object params, Class exception) throws Exception {
        AsymCipherTestVector tv =  TestData.getFirst(AsymCipherTestVector.class, alg(alg));
        if (initKey == null) {
            if (mode == ENCRYPT_MODE) {
                byte[] pub = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId())).getPub();
                initKey = otherProvider ? KeyUtil.getDummyRsaPublicKey(pub) : KeyUtil.loadPublic("RSA", pub);
            } else {
                byte[] priv = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId())).getPriv();
                initKey = otherProvider ? KeyUtil.getDummyRsaPrivateKey(priv) : KeyUtil.loadPrivate("RSA", priv);
            }
        }

        try {
            Cipher c = ProviderUtil.getCipher(alg);
            switch (initMethod) {
                case INIT_KEY_RANDOM:
                    c.init(mode, initKey, (SecureRandom) null);
                    break;
                case INIT_KEY_PARAMSPEC_RANDOM:
                    c.init(mode, initKey, (AlgorithmParameterSpec) params);
                    break;
                case INIT_KEY_PARAMS_RANDOM:
                    c.init(mode, initKey, (AlgorithmParameters) params);
                    break;
                default:
                    throw new Error("Invalid parameters in test data.");
            }
            assertNull(exception, "No exception thrown, expected " + exception);
            byte[] ctext = null;
            if (mode == ENCRYPT_MODE) {
                ctext = c.doFinal(tv.getData());

                byte[] prv = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId())).getPriv();
                PrivateKey priv = otherProvider ? KeyUtil.getDummyRsaPrivateKey(prv) : KeyUtil.loadPrivate("RSA", prv);
                c.init(Cipher.DECRYPT_MODE, priv, c.getParameters(), null);
            } else { // (this.mode == ENCRYPT_MODE)
                ctext = tv.getCiphertext();
            }
            byte[] decrypted = c.doFinal(ctext, 0, ctext.length);
            assertArrayEquals(tv.getData(), decrypted,
                    mode == ENCRYPT_MODE ? "Encrypt-decrypt failed" : "Decrypt failed");
        } catch (Exception e) {
            if (exception == null) {
                throw e;
            } else {
                assertTrue(exception.isInstance(e), "Expected exception " + exception + ", was " + e.getClass());
            }
        }
    }

}
