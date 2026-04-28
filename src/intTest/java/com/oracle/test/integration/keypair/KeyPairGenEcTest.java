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

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Test;
import org.junit.experimental.runners.Enclosed;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.DefaultUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.keyfactory.EcParamTestUtil;

import static com.oracle.test.integration.keypair.PairwiseHelper.pairwiseConsistency;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Enclosed.class)
public class KeyPairGenEcTest {

  @RunWith(Parameterized.class)
  public static class ParameterizedTests {

        static ECParameterSpec getDefaultParamSpec() {
            return switch (DefaultUtil.getExpectedKeySize("EC")) {
                case 224 -> EcParamTestUtil.P224_PARAM_SPEC;
                case 256 -> EcParamTestUtil.P256_PARAM_SPEC;
                case 384 -> EcParamTestUtil.P384_PARAM_SPEC;
                case 521 -> EcParamTestUtil.P521_PARAM_SPEC;
                default -> null;
            };
        }

        @Parameterized.Parameters(name="{0}")
        public static Collection<Object[]> aliases() {
            return Arrays.asList(
                    new Object[]{-2, getDefaultParamSpec()},
                    new Object[]{224, EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{256, EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{384, EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{521, EcParamTestUtil.P521_PARAM_SPEC},
                    new Object[]{"secp224r1", EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{"secp256r1", EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{"secp384r1", EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{"secp521r1", EcParamTestUtil.P521_PARAM_SPEC},
                    new Object[]{"SECP256R1", EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{"prime256v1", EcParamTestUtil.P256_PARAM_SPEC},

                    new Object[]{"1.3.132.0.33", EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{"1.2.840.10045.3.1.7", EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{"1.3.132.0.34", EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{"1.3.132.0.35", EcParamTestUtil.P521_PARAM_SPEC},

                    new Object[]{"P-224", EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{"P-256", EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{"P-384", EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{"P-521", EcParamTestUtil.P521_PARAM_SPEC},
                    new Object[]{"P224", EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{"P256", EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{"P384", EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{"P521", EcParamTestUtil.P521_PARAM_SPEC},
                    new Object[]{EcParamTestUtil.P224_PARAM_SPEC, EcParamTestUtil.P224_PARAM_SPEC},
                    new Object[]{EcParamTestUtil.P256_PARAM_SPEC, EcParamTestUtil.P256_PARAM_SPEC},
                    new Object[]{EcParamTestUtil.P384_PARAM_SPEC, EcParamTestUtil.P384_PARAM_SPEC},
                    new Object[]{EcParamTestUtil.P521_PARAM_SPEC, EcParamTestUtil.P521_PARAM_SPEC}
            );
        }

        private final String alg;
        private int initSize = -1;
        private AlgorithmParameterSpec initParams;
        private final ECParameterSpec expectedParams;

        public ParameterizedTests(Object params, ECParameterSpec expectedParams) {
            this.alg = "EC";
            if (params instanceof Integer) {
                this.initSize = (Integer) params;
            } else if (params instanceof String) {
                this.initParams = new ECGenParameterSpec((String) params);
            } else {
                this.initParams = (ECParameterSpec) params;
            }
            this.expectedParams = expectedParams;
        }

        @Test
        public void test() throws Exception {
            KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(this.alg);
            if (this.initSize == -2) {
                // Don't initialize.
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

            assertTrue(pub instanceof ECPublicKey);
            assertTrue(priv instanceof ECPrivateKey);
            ECPublicKey rpub = (ECPublicKey) pub;
            ECPrivateKey rpriv = (ECPrivateKey) priv;
            assertTrue(EcParamTestUtil.paramsEquals(rpub.getParams(), rpriv.getParams()));
            assertTrue(EcParamTestUtil.paramsEquals(this.expectedParams, rpub.getParams()));

            pairwiseConsistency(pub, priv);
        }
    }

  public static class SingleRun {

      @Test
      public void testMultipleSets() throws Exception {
          String propName = "jdk.security.defaultKeySize";
          String existingValue = System.setProperty(propName, "EC:384,RSA:1024,EC:256");
          KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator("EC");
          KeyPair kp = kpg.generateKeyPair();
          ECPublicKey pubKey = (ECPublicKey)kp.getPublic();
          int field = pubKey.getParams().getCurve().getField().getFieldSize();
          assertEquals(field, 256); // Explicit check against value set in the test.
          if (existingValue == null) {
              existingValue = "";
          }
          System.setProperty(propName, existingValue);
      }

      @Test
      public void testInvalidSets() throws Exception {
          String propName = "jdk.security.defaultKeySize";
          String existingValue = System.setProperty(propName, "EC:384,RSA:1024,EC:224");
          KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator("EC");
          KeyPair kp = kpg.generateKeyPair();
          ECPublicKey pubKey = (ECPublicKey)kp.getPublic();
          int field = pubKey.getParams().getCurve().getField().getFieldSize();
          assertEquals(field, 384); // Explicit check against value set in the test.
          if (existingValue == null) {
              existingValue = "";
          }
          System.setProperty(propName, existingValue);
      }
  }

}
