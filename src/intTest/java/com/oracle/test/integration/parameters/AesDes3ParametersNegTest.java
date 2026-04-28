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

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.spec.IvParameterSpec;

import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;

@RunWith(Parameterized.class)
public class AesDes3ParametersNegTest {
    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        return Arrays.asList(
                new Object[]{
                        "AES", new IvParameterSpec(hexStringToByteArray("12341234123412341234123412341234")), hexStringToByteArray("041012341234123412341234123412341234")
                },
                new Object[]{
                        "DESede", new IvParameterSpec(hexStringToByteArray("1234123412341234")), hexStringToByteArray("04081234123412341234")
                }
        );
    }
    private final String alg;
    private final IvParameterSpec spec;
    private final byte[] der;

    private AlgorithmParameters params;

    public AesDes3ParametersNegTest(String alg, IvParameterSpec spec, byte[] ivDer) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.equalsIgnoreCase("DESede"));
        this.alg = alg;
        this.spec = spec;
        this.der = ivDer;
    }
    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters(this.alg);
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecWrongIvLength() throws Exception {
        params.init(new IvParameterSpec(new byte[this.spec.getIV().length - 1]));
        assertArrayEquals(der, params.getEncoded());
    }

    @Test(expected = IOException.class)
    public void initDERInvalidOctetStringId() throws Exception {
        params.init(new byte[der.length]);
    }

    @Test(expected = IOException.class)
    public void initDERInvalidLenByte() throws Exception {
        byte[] tt = Arrays.copyOf(der, der.length);
        tt[1] = 2;
        params.init(tt);
    }

    @Test(expected = IOException.class)
    public void initDerIvWrongSize() throws Exception {
        params.init(TestUtil.concat(der, hexStringToByteArray("8888")));
    }
}
