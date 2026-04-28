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

package com.oracle.test.integration.parameters;

import java.math.BigInteger;
import java.security.AlgorithmParameters;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.DSAParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.keyfactory.EcParamTestUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class EcParametersTest {

    @Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        return Arrays.asList(
                new Object[]{"secp224r1", "1.3.132.0.33", new String[]{"1.3.132.0.33", "P-224", "P224"}, EcParamTestUtil.P224_PARAM_SPEC, TestUtil.hexStringToByteArray("06052B81040021")},
                new Object[]{"secp256r1", "1.2.840.10045.3.1.7", new String[]{"1.2.840.10045.3.1.7", "P-256", "P256", "prime256v1"}, EcParamTestUtil.P256_PARAM_SPEC, TestUtil.hexStringToByteArray("06082A8648CE3D030107")},
                new Object[]{"secp384r1", "1.3.132.0.34", new String[]{"1.3.132.0.34", "P-384", "P384"}, EcParamTestUtil.P384_PARAM_SPEC, TestUtil.hexStringToByteArray("06052B81040022")},
                new Object[]{"secp521r1", "1.3.132.0.35", new String[]{"1.3.132.0.35", "P-521", "P521"}, EcParamTestUtil.P521_PARAM_SPEC, TestUtil.hexStringToByteArray("06052B81040023")}
        );
    }

    private final String curveName;
    private final String curveOid;
    private final String[] aliases;
    private final ECParameterSpec spec;
    private final byte[] encoding;

    private AlgorithmParameters params;

    public EcParametersTest(String curveName, String curveOid, String[] aliases, ECParameterSpec spec, byte[] encoding) {
        this.curveName = curveName;
        this.curveOid = curveOid;
        this.aliases = aliases;
        this.spec = spec;
        this.encoding = encoding;
    }

    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters("EC");
    }

    @Test
    public void initEncoded() throws Exception {
        params.init(encoding);

        verifyParams(params);
    }

    @Test
    public void initEncodedFormat() throws Exception {
        params.init(encoding, "ignored");

        verifyParams(params);
    }

    @Test
    public void initECParameterSpec() throws Exception {
        params.init(this.spec);

        verifyParams(params);
    }

    @Test
    public void initECGenParameterSpec() throws Exception {
        params.init(new ECGenParameterSpec(this.curveName));

        verifyParams(params);
    }

    @Test
    public void initECGenParameterSpecAliases() throws Exception {
        for (String alias : this.aliases) {
            params = ProviderUtil.getAlgorithmParameters("EC");
            params.init(new ECGenParameterSpec(alias));

            verifyParams(params);
        }
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initECGenParameterSpecUnknownCurve() throws Exception {
        params.init(new ECGenParameterSpec("yabba"));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initBadSpec() throws Exception {
        params.init(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test
    public void testToString() throws Exception {
        params.init(new ECGenParameterSpec(this.curveName));
        String s = params.toString();
        assertEquals("EC Parameters (" + this.curveName + ")", s);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecNull() throws Exception {
        params.init(new ECGenParameterSpec(this.curveName));
        params.getParameterSpec(null);
    }

    @Test
    public void getParameterSpecInterfaceAlgorithmParameterSpec() throws Exception {
        params.init(new ECGenParameterSpec(this.curveName));
        AlgorithmParameterSpec getSpec = params.getParameterSpec(AlgorithmParameterSpec.class);
        assertTrue(getSpec instanceof ECParameterSpec);
        verifyParamSpec((ECParameterSpec) getSpec);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecBadSpec() throws Exception {
        params.init(new ECGenParameterSpec(this.curveName));
        params.getParameterSpec(DSAParameterSpec.class);
    }

    private void verifyParams(AlgorithmParameters params) throws Exception {
        verifyParamSpec(params.getParameterSpec(ECParameterSpec.class));
    }

    private void verifyParamSpec(ECParameterSpec getSpec) throws Exception {
        assertTrue(EcParamTestUtil.paramsEquals(this.spec, getSpec));
        ECGenParameterSpec getGenSpec = params.getParameterSpec(ECGenParameterSpec.class);
        assertEquals(this.curveOid, getGenSpec.getName());
        assertArrayEquals(this.encoding, params.getEncoded());
        assertArrayEquals(this.encoding, params.getEncoded("other"));
    }

}
