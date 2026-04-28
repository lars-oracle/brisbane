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

package com.oracle.test.integration.signature;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.PublicKey;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.AlgorithmUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.Assert.assertEquals;


@RunWith(Parameterized.class)
public class RsaPssDigestSigTest {

    @Parameterized.Parameters(name = "digestSignature({0}) - digestLength ({1})")
    public static Collection<Object[]> digestSignatures() {
        return Arrays.asList(
                new Object[] {"SHA1withRSAandMGF1", 20},
                new Object[] {"SHA224withRSAandMGF1", 28},
                new Object[] {"SHA256withRSAandMGF1", 32},
                new Object[] {"SHA384withRSAandMGF1", 48},
                new Object[] {"SHA512withRSAandMGF1", 64}
        );
    }

    private final String digestSignature;
    private final int digestLength;
    PublicKey pubKey;

    public RsaPssDigestSigTest(String digestSignature, int digestLength) throws Exception {
        String digest = AlgorithmUtil.digestFromDigestSignature(digestSignature);
        Assume.assumeTrue(FipsProviderInfoUtil.isSHA1DigestSignatureSupported() || !digest.equals("SHA-1"));
        this.digestSignature = digestSignature;
        this.digestLength = digestLength;

        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.alg("RSA"));
        pubKey = KeyUtil.loadPublic(kp.getAlg(), kp.getPub());
    }

    @Test
    public void testDefaultSaltLen() throws Exception {
        final Signature signature = ProviderUtil.getSignature(digestSignature);
        final AlgorithmParameters parameters = signature.getParameters();
        final PSSParameterSpec pssParameters = parameters.getParameterSpec(PSSParameterSpec.class);
        // By default, the salt length should match the digest length
        assertEquals(digestLength, pssParameters.getSaltLength());
    }

    @Test
    public void testMaxSaltLen() throws Exception {
        final String digest = AlgorithmUtil.digestFromDigestSignature(digestSignature);
        final Signature signature = ProviderUtil.getSignature(digestSignature);
        signature.initVerify(this.pubKey);

        // It should be possible to set PSS parameters with a salt length up to the message digest length.
        signature.setParameter(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest), digestLength,
                PSSParameterSpec.TRAILER_FIELD_BC));

        try {
            signature.setParameter(new PSSParameterSpec(digest, "MGF1", new MGF1ParameterSpec(digest),
                    digestLength + 1, PSSParameterSpec.TRAILER_FIELD_BC));
            Assert.fail("It should not be possible to set PSS parameters with a salt length longer than the message digest length");
        } catch (InvalidAlgorithmParameterException e) {
            // Expected exception.
        }
    }
}
