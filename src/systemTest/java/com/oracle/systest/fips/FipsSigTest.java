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

package com.oracle.systest.fips;

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.KeyPairs;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.EnvUtil.FipsPolicy.STRICT;
import static com.oracle.systest.SysTestUtil.isFipsException;
import static com.oracle.systest.fips.OperationResult.FIPS_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.OTHER_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.SUCCESS;
import static java.security.spec.PSSParameterSpec.TRAILER_FIELD_BC;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class FipsSigTest {

    static final String[] DIGEST_NAMES = FipsProviderInfoUtil.isSHA1DigestSignatureSupported() ?
            new String[]{"SHA-1", "SHA-224", "SHA-256", "SHA-384", "SHA-512"} :
            new String[]{"SHA-224", "SHA-256", "SHA-384", "SHA-512"};
    static final String[] DSA_PARAM_SIZES = new String[]{"1024-160", "2048-224", "2048-256"};
    static final String[] EC_CURVE_NAMES = new String[]{"secp192r1", "secp224r1", "secp256r1", "secp384r1", "secp521r1"};
    static final int[] RSA_KEY_SIZES = new int[]{1024, 1536, 2048, 3072};

    private final String alg;
    private final AlgorithmParameterSpec algParamSpec;
    private final OperationResult expectedSign;
    private final OperationResult expectedVrfy;

    PrivateKey privKey;
    PublicKey pubKey;

    static int getDigestByteLength(String digestName) {
        int length = Integer.parseInt(digestName.split("-")[1]);
        return length == 1 ? 20 : length / 8;
    }

    static String getSignAlg(String digestName, String KeyName) {
        return digestName.replace("-", "") + "with" + KeyName + (KeyName.equals("EC") ? "DSA" : "");
    }

    static private boolean isDSASupported() {
        return (EnvUtil.getPolicy() != STRICT) && FipsProviderInfoUtil.isDSASupported();
    }

    static private boolean isSHA1DigestSignatureSupported() {
        return (EnvUtil.getPolicy() != STRICT) && FipsProviderInfoUtil.isSHA1DigestSignatureSupported();
    }

    public FipsSigTest(EnvUtil.FipsPolicy policy, String keyAlg, String secParam, String sigAlg, AlgorithmParameterSpec algParamSpec, OperationResult sign, OperationResult vrfy) throws Exception {
        Assume.assumeTrue(isDSASupported() || !keyAlg.equalsIgnoreCase("DSA"));
        Assume.assumeTrue(isSHA1DigestSignatureSupported() || !sigAlg.toUpperCase().startsWith("SHA1"));
        this.alg = sigAlg;
        this.algParamSpec = algParamSpec;
        this.expectedSign = sign;
        this.expectedVrfy = vrfy;

        List<KeyPairTestData> list = new ArrayList<>(Arrays.asList(TestData.loadJson("keypairs_nonfips.json", KeyPairTestData[].class)));
        list.addAll(Arrays.asList(TestData.loadJson(KeyPairTestData[].class)));
        KeyPairs kps = new KeyPairs(list);

        KeyPairTestData kp = kps.getAny(keyAlg, secParam);
        privKey = kp.getGenericPrivateKey();
        pubKey = kp.getGenericPublicKey();
    }

    @Parameterized.Parameters(name="policy={0}:{1}:{2}:{3}:{4}:expect(sig,ver)=({5},{6})")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> p = new ArrayList<>();
        EnvUtil.FipsPolicy policy = EnvUtil.getPolicy();
        if (policy == EnvUtil.FipsPolicy.NONE) {
            for (int keySize : RSA_KEY_SIZES) {
                for (String digestName : DIGEST_NAMES) {
                    p.add(new Object[]{policy, "RSA", String.valueOf(keySize), getSignAlg(digestName, "RSA"), null,
                            (keySize < 2048) ||  digestName.equals("SHA-1") ? OTHER_EXCEPTION: SUCCESS, SUCCESS});

                    p.add(new Object[]{policy, "RSA", String.valueOf(keySize), "RSASSA-PSS", new PSSParameterSpec(digestName, "MGF1",
                            new MGF1ParameterSpec(digestName), getDigestByteLength(digestName), TRAILER_FIELD_BC),
                            keySize < 2048 || digestName.equals("SHA-1") ? OTHER_EXCEPTION : SUCCESS, SUCCESS});

                    // OpenSSL does not get to validate the salt length until the signature is generated or verified
                    // and thus OpenSSL's behavior is not tested in an initSign() or initVerify() call.
                }
            }
            for (String curveName : EC_CURVE_NAMES) {
                for (String digestName : DIGEST_NAMES) {
                    // Although SP 800-131A Rev.2 allows ECDSA signature validation for curves with 160 <= len(n) < 224
                    // Jipher (like the SunEC provider) does not support these weak curves, even for verification.
                    OperationResult verify = curveName.equals("secp192r1") ? OTHER_EXCEPTION : SUCCESS;

                    // All versions of the OpenSSL FIPS provider disallow SHA-1 to be used for ECDSA signature generation.
                    OperationResult generate = curveName.equals("secp192r1") || digestName.equals("SHA-1") ?
                            OTHER_EXCEPTION: SUCCESS;

                    p.add(new Object[]{policy, "EC", curveName, getSignAlg(digestName, "EC"), null,
                            generate, verify});
                }
            }
            for (String paramSize : DSA_PARAM_SIZES) {
                for (String digestName : DIGEST_NAMES) {
                    p.add(new Object[]{policy, "DSA", paramSize, getSignAlg(digestName, "DSA"), null, OTHER_EXCEPTION, SUCCESS});
                }
            }
        } else {
            for (int keySize : RSA_KEY_SIZES) {
                for (String digestName : DIGEST_NAMES) {
                    OperationResult generate = keySize < 2048 || digestName.equals("SHA-1") ? FIPS_EXCEPTION : SUCCESS;
                    OperationResult verify = (policy == STRICT) ? generate : SUCCESS;

                    p.add(new Object[]{policy, "RSA", String.valueOf(keySize), getSignAlg(digestName, "RSA"), null,
                            generate, verify});

                    p.add(new Object[]{policy, "RSA", String.valueOf(keySize), "RSASSA-PSS", new PSSParameterSpec(digestName, "MGF1",
                            new MGF1ParameterSpec(digestName), getDigestByteLength(digestName), TRAILER_FIELD_BC),
                            generate, verify});

                    generate = (generate == FIPS_EXCEPTION) ? generate : OTHER_EXCEPTION;
                    verify   = (verify   == FIPS_EXCEPTION) ? verify   : OTHER_EXCEPTION;
                    p.add(new Object[]{policy, "RSA", String.valueOf(keySize), "RSASSA-PSS", new PSSParameterSpec(digestName, "MGF1",
                            new MGF1ParameterSpec(digestName), getDigestByteLength(digestName) + 1, TRAILER_FIELD_BC),
                            generate, verify});
                }
            }
            for (String curveName : EC_CURVE_NAMES) {
                for (String digestName : DIGEST_NAMES) {
                    // Although SP 800-131A Rev.2 allows ECDSA signature validation for curves with 160 <= len(n) < 224
                    // Jipher (like the SunEC provider) does not support these weak curves, even for verification.
                    OperationResult generate = digestName.equals("SHA-1") ? FIPS_EXCEPTION :
                            curveName.equals("secp192r1") ? OTHER_EXCEPTION : SUCCESS;
                    OperationResult verify = (policy == STRICT) ? generate : (curveName.equals("secp192r1") ?  OTHER_EXCEPTION : SUCCESS);

                    p.add(new Object[]{policy, "EC", curveName, getSignAlg(digestName, "EC"), null,
                            generate, verify});
                }
            }
            for (String paramSize : DSA_PARAM_SIZES) {
                for (String digestName : DIGEST_NAMES) {
                    p.add(new Object[]{policy, "DSA", paramSize, getSignAlg(digestName, "DSA"), null,
                            FIPS_EXCEPTION, SUCCESS});
                }
            }
        }
        return p;
    }

    @Test
    public void sign() throws Exception {
        try {
            Signature sig = ProviderUtil.getSignature(this.alg);
            // Disable delayed provider selection, and confirm expected provider name
            assertEquals("JipherJCE", sig.getProvider().getName());
            sig.initSign(this.privKey);
            if (this.algParamSpec != null) {
                sig.setParameter(this.algParamSpec);
            }
            assertEquals(this.expectedSign, SUCCESS);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedSign, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedSign, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedSign, OTHER_EXCEPTION);
        }
    }

    @Test
    public void vrfy() throws Exception {
        try {
            Signature sig = ProviderUtil.getSignature(this.alg);
            // Disable delayed provider selection, and confirm expected provider name
            assertEquals("JipherJCE", sig.getProvider().getName());
            sig.initVerify(this.pubKey);
            if (this.algParamSpec != null) {
                sig.setParameter(this.algParamSpec);
            }
            assertEquals(this.expectedVrfy, SUCCESS);
        } catch (InvalidAlgorithmParameterException | InvalidKeyException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedVrfy, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedVrfy, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedVrfy, OTHER_EXCEPTION);
        }
    }
}
