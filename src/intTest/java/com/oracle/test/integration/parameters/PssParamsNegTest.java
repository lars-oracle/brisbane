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
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;
import javax.crypto.spec.DHGenParameterSpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;

public class PssParamsNegTest {

    private AlgorithmParameters ap;

    @Before
    public void setUp() throws Exception {
        this.ap = ProviderUtil.getAlgorithmParameters("RSASSA-PSS");
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecInvalidMgfAlg() throws Exception {
        this.ap.init(new PSSParameterSpec("SHA-224", "MGF2", new MGF1ParameterSpec("SHA-1"), 20, 1));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecNullMgfSpec() throws Exception {
        this.ap.init(new PSSParameterSpec("SHA-224", "MGF1", null, 32, 1));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecInvalidMgfSpec() throws Exception {
        this.ap.init(new PSSParameterSpec("SHA-224", "MGF1", new DHGenParameterSpec(1024,160), 32, 1));
    }

    @Test(expected = IllegalArgumentException.class)
    public void initGetEncodedInvalidFormat() throws Exception {
        this.ap.init(new PSSParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, 20, PSSParameterSpec.TRAILER_FIELD_BC));
        byte[] encoded = this.ap.getEncoded("Invalid");
    }

    @Test(expected = IllegalArgumentException.class)
    public void initEncodedInvalidFormat() throws Exception {
        this.ap.init(hexStringToByteArray("3000"), "Invalid");
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidBER() throws Exception {
        this.ap.init(hexStringToByteArray("3016A0"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidExplicitTagValue() throws Exception {
        this.ap.init(hexStringToByteArray("3016A60F300D06096086480165030402010500A203020120"));
    }

    @Test(expected = IOException.class)
    public void initEncodedMissingDigestAlgParamNull() throws Exception {
        this.ap.init(hexStringToByteArray("3037A00d300b060960864801650304020105A11C301A06092A864886F70D010108300D06096086480165030402020500A203020140A303020102"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidPssDigestOid() throws Exception {
        this.ap.init(hexStringToByteArray("3039A00F300D06096086480165090402010500A11C301A06092A864886F70D010108300D06096086480165030402020500A203020140A303020102"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidMgfOid() throws Exception {
        this.ap.init(hexStringToByteArray("3039A00F300D06096086480165030402010500A11C301A06092A864886F70D010908300D06096086480165030402020500A203020140A303020102"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidMgf1DigestOid() throws Exception {
        this.ap.init(hexStringToByteArray("3039A00F300D06096086480165030402010500A11C301A06092A864886F70D010108300D06096086480165090402020500A203020140A303020102"));
    }

}
