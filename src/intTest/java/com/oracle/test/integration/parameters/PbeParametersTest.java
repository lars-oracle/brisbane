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

import java.security.AlgorithmParameters;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.bytesToHex;
import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;

public class PbeParametersTest {
    private static final int ITERATION_COUNT = 10000;
    private static final byte[] SALT = hexStringToByteArray("9F7571C242DF90AF7A260D52E9FECFCF4003B924");
    private static final byte[] ENCODED = hexStringToByteArray("301A04149F7571C242DF90AF7A260D52E9FECFCF4003B92402022710");
    private static final String FORMAT = "ASN.1";

    AlgorithmParameters ap;

    @Before
    public void setUp() throws Exception {
        ap = ProviderUtil.getAlgorithmParameters("PBE");
    }

    @Test
    public void initAlgorithmParameterSpecTest() throws Exception {
        ap.init(new PBEParameterSpec(SALT, ITERATION_COUNT));
        checkSpec();
    }

    @Test
    public void initEncodedTest() throws Exception {
        ap.init(ENCODED, FORMAT);
        checkSpec();
    }

    @Test
    public void getEncodedTest() throws Exception {
        ap.init(new PBEParameterSpec(SALT, ITERATION_COUNT));
        Assert.assertArrayEquals(ENCODED, ap.getEncoded(FORMAT));
    }

    @Test
    public void toStringTest() throws Exception {
        ap.init(new PBEParameterSpec(SALT, ITERATION_COUNT));
        Assert.assertEquals("PBE Parameters [ salt=" + bytesToHex(SALT) + ", iterationCount=" + ITERATION_COUNT + " ]", ap.toString());
    }

    private void checkSpec() throws Exception {
        PBEParameterSpec spec = ap.getParameterSpec(PBEParameterSpec.class);
        Assert.assertArrayEquals(SALT, spec.getSalt());
        Assert.assertEquals(ITERATION_COUNT, spec.getIterationCount());
    }

    @Test (expected = InvalidParameterSpecException.class)
    public void initAlgorithmParameterInvalidSpecNegTest() throws Exception {
        ap.init(new IvParameterSpec(new byte[16]));
    }

    @Test (expected = InvalidParameterSpecException.class)
    public void getInvalidSpecNegTest() throws Exception {
        ap.init(new PBEParameterSpec(SALT, ITERATION_COUNT));
        ap.getParameterSpec(IvParameterSpec.class);
    }

    @Test (expected = InvalidParameterSpecException.class)
    public void getNullSpecNegTest() throws Exception {
        ap.init(new PBEParameterSpec(SALT, ITERATION_COUNT));
        ap.getParameterSpec(null);
    }
}
