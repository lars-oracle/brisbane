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

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.MGF1ParameterSpec;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.junit.jupiter.api.AfterAll;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class AsymCipherInitAlgParamTest {

    static final byte[] P_SRC = {(byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x01, (byte) 0x02, (byte) 0x02, (byte) 0x02, (byte) 0x02};
    static final PSource.PSpecified NON_DEFAULT = new PSource.PSpecified(P_SRC);

    static final IvParameterSpec IV = new IvParameterSpec(new byte[16]);

    static final OAEPParameterSpec OAEP_SHA1_DEFAULT   = new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    static final OAEPParameterSpec OAEP_SHA224_DEFAULT = new OAEPParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    static final OAEPParameterSpec OAEP_SHA256_DEFAULT = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    static final OAEPParameterSpec OAEP_SHA384_DEFAULT = new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);
    static final OAEPParameterSpec OAEP_SHA512_DEFAULT = new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT);

    static final OAEPParameterSpec OAEP_SHA1_NON_DEFAULT   = new OAEPParameterSpec("SHA-1", "MGF1",   MGF1ParameterSpec.SHA1, NON_DEFAULT);
    static final OAEPParameterSpec OAEP_SHA224_NON_DEFAULT = new OAEPParameterSpec("SHA-224", "MGF1", MGF1ParameterSpec.SHA1, NON_DEFAULT);
    static final OAEPParameterSpec OAEP_SHA256_NON_DEFAULT = new OAEPParameterSpec("SHA-256", "MGF1", MGF1ParameterSpec.SHA1, NON_DEFAULT);
    static final OAEPParameterSpec OAEP_SHA384_NON_DEFAULT = new OAEPParameterSpec("SHA-384", "MGF1", MGF1ParameterSpec.SHA1, NON_DEFAULT);
    static final OAEPParameterSpec OAEP_SHA512_NON_DEFAULT = new OAEPParameterSpec("SHA-512", "MGF1", MGF1ParameterSpec.SHA1, NON_DEFAULT);

    static PublicKey PUBLIC_KEY;

    // Do not set PUBLIC_KEY in a static initializer as doing so results in the
    // OpenSSL Object Leak test suite flagging it as an allocation that is never freed
    @BeforeAll
    static void loadPublicKey() throws Exception {
        PUBLIC_KEY = KeyUtil.loadPublic("RSA", TestData.getFirst(KeyPairTestData.class, alg("RSA").secParam("2048")).getPub());
    }

    @AfterAll
    static void unloadPublicKey() {
        PUBLIC_KEY = null;
    }

    public AsymCipherInitAlgParamTest() {}

    private static Stream<Arguments> createTransformDefaultExplicitParamSpecsException() {
        return Stream.of(
                Arguments.of("RSA/ECB/OAEPPadding",  OAEP_SHA1_DEFAULT, OAEP_SHA512_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-1andMGF1Padding", OAEP_SHA1_DEFAULT, OAEP_SHA1_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-1andMGF1Padding", OAEP_SHA1_DEFAULT, OAEP_SHA512_NON_DEFAULT, InvalidAlgorithmParameterException.class),
                Arguments.of("RSA/ECB/OAEPWithSHA-224andMGF1Padding", OAEP_SHA224_DEFAULT, OAEP_SHA224_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-224andMGF1Padding", OAEP_SHA224_DEFAULT, OAEP_SHA512_NON_DEFAULT, InvalidAlgorithmParameterException.class),
                Arguments.of("RSA/ECB/OAEPWithSHA-256andMGF1Padding", OAEP_SHA256_DEFAULT, OAEP_SHA256_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-256andMGF1Padding", OAEP_SHA256_DEFAULT, OAEP_SHA512_NON_DEFAULT, InvalidAlgorithmParameterException.class),
                Arguments.of("RSA/ECB/OAEPWithSHA-384andMGF1Padding", OAEP_SHA384_DEFAULT, OAEP_SHA384_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-384andMGF1Padding", OAEP_SHA384_DEFAULT, OAEP_SHA512_NON_DEFAULT, InvalidAlgorithmParameterException.class),
                Arguments.of("RSA/ECB/OAEPWithSHA-512andMGF1Padding", OAEP_SHA512_DEFAULT, OAEP_SHA512_NON_DEFAULT, null),
                Arguments.of("RSA/ECB/OAEPWithSHA-512andMGF1Padding", OAEP_SHA512_DEFAULT, OAEP_SHA1_NON_DEFAULT, InvalidAlgorithmParameterException.class)
        );
    }

    @ParameterizedTest(name = "{0}")
    @MethodSource("createTransformDefaultExplicitParamSpecsException")
    public void testDefaultParam(String transform, AlgorithmParameterSpec defaultParameterSpec, AlgorithmParameterSpec explicitParameterSpec, Class exception) throws Exception {
        if (defaultParameterSpec != null) {
            // Check that the default and explicit parameter specs are distinct and thus this test is meaningful
            assertFalse(equals(defaultParameterSpec, explicitParameterSpec),
                    "Default parameter spec equals explicit parameter spec");
        }

        try {
            Cipher cipher = ProviderUtil.getCipher(transform);

            // Validate the expected default parameters when no explicit parameters are specified
            cipher.init(Cipher.ENCRYPT_MODE, PUBLIC_KEY);
            AlgorithmParameters algorithmParams = cipher.getParameters();
            if (defaultParameterSpec == null) {
                assertNull(algorithmParams);
            } else {
                assertTrue(equals(algorithmParams.getParameterSpec(OAEPParameterSpec.class), defaultParameterSpec),
                        "Unexpected default parameter spec");
            }

            // Validate the expected explicit parameters when explicit parameters are specified
            cipher.init(Cipher.ENCRYPT_MODE, PUBLIC_KEY, explicitParameterSpec);
            algorithmParams = cipher.getParameters();
            assertTrue(equals(algorithmParams.getParameterSpec(OAEPParameterSpec.class), explicitParameterSpec),
                    "Unexpected explicit parameter spec");

            // Validate that the default parameters are reestablished
            // when the object is re-initialised without specifying explicit parameters.
            cipher.init(Cipher.ENCRYPT_MODE, PUBLIC_KEY);
            algorithmParams = cipher.getParameters();
            if (defaultParameterSpec == null) {
                assertNull(algorithmParams);
            } else {
                assertTrue(equals(algorithmParams.getParameterSpec(OAEPParameterSpec.class), defaultParameterSpec),
                        "Unexpected default parameter spec");
            }
        } catch (Exception e) {
            if (exception == null) {
                throw e;
            } else {
                assertTrue(exception.isInstance(e), "Expected exception " + exception + ", was " + e.getClass());
            }
        }
    }

    // Returns true if the specified pair of AlgorithmParameterSpec's are equal
    static boolean equals(AlgorithmParameterSpec a, AlgorithmParameterSpec b) {
        if (a.getClass() != b.getClass()) {
            return false;
        }
        if (a instanceof OAEPParameterSpec specA) {
            OAEPParameterSpec specB = (OAEPParameterSpec) b;

            if (!specA.getDigestAlgorithm().equals(specB.getDigestAlgorithm())) {
                return false;
            }
            if (!specA.getMGFAlgorithm().equals(specB.getMGFAlgorithm())) {
                return false;
            }
            if (!specA.getMGFParameters().toString().equals(specB.getMGFParameters().toString())) {
                return false;
            }
            // Test assumes that by construction observed data can only be one of
            // PSource.PSpecified.DEFAULT or AsymCipherInitAlgParamTest.NON_DEFAULT
            if (specA.getPSource() != specB.getPSource()) {
                return false;
            }
        } else {
            throw new RuntimeException("Test does not support" + a.getClass().getName());
        }
        return true;
    }
}
