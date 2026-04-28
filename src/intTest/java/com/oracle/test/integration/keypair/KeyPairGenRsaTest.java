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

package com.oracle.test.integration.keypair;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.DefaultUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.test.integration.keypair.PairwiseHelper.pairwiseConsistency;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Enclosed.class)
public class KeyPairGenRsaTest {

    @RunWith(Parameterized.class)
    public static class ParameterizedTests {

        @Parameterized.Parameters(name="{index}: {0}:{1}")
        public static Collection<Object[]> aliases() {
            return Arrays.asList(
                    new Object[]{"RSA", -2, null},
                    new Object[]{"RSA", 2048, null},
                    new Object[]{"RSA", 2096, null},
                    new Object[]{"RSA", 3072, null},
                    new Object[]{"RSA", 3080, null},
                    new Object[]{"RSA", -1, new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(170293))},
                    new Object[]{"RSA", -1, new RSAKeyGenParameterSpec(2048, null)},
                    new Object[]{"RSA", -1, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)},
                    new Object[]{"RSASSA-PSS", -2, null},
                    new Object[]{"RSASSA-PSS", 2048, null},
                    new Object[]{"RSASSA-PSS", 2096, null},
                    new Object[]{"RSASSA-PSS", 3072, null},
                    new Object[]{"RSASSA-PSS", 3080, null},
                    new Object[]{"RSASSA-PSS", -1, new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(170293))},
                    new Object[]{"RSASSA-PSS", -1, new RSAKeyGenParameterSpec(2048, null)},
                    new Object[]{"RSASSA-PSS", -1, new RSAKeyGenParameterSpec(4096, RSAKeyGenParameterSpec.F4)}
            );
        }
        private final String alg;
        private final int initSize;
        private final AlgorithmParameterSpec initParams;

        public ParameterizedTests(String alg, int initSize, RSAKeyGenParameterSpec spec) {
            this.alg = alg;
            this.initSize = initSize;
            this.initParams = spec;
        }

        @Test
        public void test() throws Exception {
            KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(this.alg);
            if (this.initSize == -2) {
            // Test no initialization.
            } else if (this.initSize != -1) {
                kpg.initialize(this.initSize);
            } else {
                kpg.initialize(this.initParams);
            }
            KeyPair kp = kpg.generateKeyPair();
            checkKeyPair(kp);
        }

        void checkKeyPair(KeyPair kp) throws Exception {
            PublicKey pub = kp.getPublic();
            PrivateKey priv = kp.getPrivate();

            assertTrue(pub instanceof RSAPublicKey);
            assertTrue(priv instanceof RSAPrivateCrtKey);
            RSAPublicKey rpub = (RSAPublicKey) pub;
            RSAPrivateCrtKey rpriv = (RSAPrivateCrtKey) priv;
            assertEquals(rpub.getPublicExponent(), rpriv.getPublicExponent());
            assertEquals(rpub.getModulus(), rpriv.getModulus());
            final int keySize = ((RSAPublicKey) pub).getModulus().bitLength();
            int expectedKeySize = 0;
            final BigInteger pubE = ((RSAPublicKey) pub).getPublicExponent();
            BigInteger expectedPubE = null;
            // Direct Key Size case.
            if (this.initSize > 0) {
                expectedKeySize = this.initSize;
                expectedPubE = BigInteger.valueOf(65537);
            } else if (this.initSize == -1) { // Init via params case.
                RSAKeyGenParameterSpec spec = (RSAKeyGenParameterSpec) this.initParams;
                expectedKeySize = spec.getKeysize();
                expectedPubE = spec.getPublicExponent() != null ? spec.getPublicExponent()
                        : BigInteger.valueOf(65537);
            } else if (this.initSize == -2) { // No init case.
                expectedKeySize = DefaultUtil.getExpectedKeySize("RSA");
                expectedPubE = BigInteger.valueOf(65537);
            }
            assertEquals(expectedKeySize, keySize);
            assertEquals(expectedPubE, pubE);

            pairwiseConsistency(pub, priv);
        }
    }

    public static class SingleRun {
        @Test
        public void testDefaults() throws Exception {
            System.setProperty("jdk.security.defaultKeySize", "RSA:4096");
            KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator("RSA");
            KeyPair kp = kpg.generateKeyPair();
            int effectiveModLen = ((RSAPublicKey) kp.getPublic()).getModulus().bitLength();
            assertEquals(4096, effectiveModLen);
        }
    }
}
