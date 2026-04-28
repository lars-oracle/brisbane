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
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.spec.DHParameterSpec;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.ParameterTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;

@RunWith(Parameterized.class)
public class DhParametersTest {

    @Parameters(name = "{0}[{index}]")
    public static Collection<Object[]> data() throws Exception {
        List<Object[]> all = new ArrayList<>();
        for (ParameterTestData td : TestData.get(ParameterTestData.class, alg("DH"))) {
            all.add(new Object[] {td.getSecParam(), td});
        }
        return all;
    }

    private final ParameterTestData paramData;
    private final DHParameterSpec spec;

    private AlgorithmParameters params;

    public DhParametersTest(String secParams, ParameterTestData pd) {
        this.paramData = pd;

        this.spec = new DHParameterSpec(new BigInteger(1, paramData.getParamParts().getP()),
                new BigInteger(1, paramData.getParamParts().getG()));
    }

    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters("DH");
    }

    @Test
    public void initEncoded() throws Exception {
        params.init(paramData.getEncoding());

        verifyParams(params);
    }

    @Test
    public void initEncodedFormat() throws Exception {
        params.init(paramData.getEncoding(), "ignored");

        verifyParams(params);
    }

    @Test
    public void initDHParameterSpec() throws Exception {
        params.init(this.spec);

        verifyParams(params);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initBadSpec() throws Exception {
        params.init(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test
    public void testToString() throws Exception {
        params.init(this.spec);
        String s = params.toString();
        assertTrue(s.startsWith("DH Parameters (P="));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecNull() throws Exception {
        params.init(this.spec);
        params.getParameterSpec(null);
    }

    @Test
    public void getParameterSpecInterfaceAlgorithmParameterSpec() throws Exception {
        params.init(this.spec);
        AlgorithmParameterSpec getSpec = params.getParameterSpec(AlgorithmParameterSpec.class);
        assertTrue(getSpec instanceof DHParameterSpec);
        verifyParamSpec((DHParameterSpec) getSpec);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void getParameterSpecBadSpec() throws Exception {
        params.init(this.spec);
        params.getParameterSpec(RSAKeyGenParameterSpec.class);
    }

    @Test
    public void getEncoded() throws Exception {
        params.init(this.spec);
        byte[] der = params.getEncoded();

        assertArrayEquals(paramData.getEncoding(), der);
    }

    @Test
    public void getEncodedFormat() throws Exception {
        params.init(this.spec);
        byte[] der = params.getEncoded("ignore");

        assertArrayEquals(paramData.getEncoding(), der);
    }

    private void verifyParams(AlgorithmParameters params) throws Exception {
        verifyParamSpec(params.getParameterSpec(DHParameterSpec.class));
    }

    private void verifyParamSpec(DHParameterSpec getSpec) throws Exception {
        assertEquals(this.spec.getP(), getSpec.getP());
        assertEquals(this.spec.getG(), getSpec.getG());
    }

}
