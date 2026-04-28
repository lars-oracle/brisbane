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
import javax.crypto.spec.DHGenParameterSpec;
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;

public class OaepParamsNegTest {

    private AlgorithmParameters ap;

    @Before
    public void setUp() throws Exception {
        this.ap = ProviderUtil.getAlgorithmParameters("OAEP");
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecInvalidMgfAlg() throws Exception {
        this.ap.init(new OAEPParameterSpec("SHA-224", "MGF2", new MGF1ParameterSpec("SHA-224"), PSource.PSpecified.DEFAULT));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecNullMgfSpec() throws Exception {
        this.ap.init(new OAEPParameterSpec("SHA-224", "MGF1", null, PSource.PSpecified.DEFAULT));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecInvalidMgfSpec() throws Exception {
        this.ap.init(new OAEPParameterSpec("SHA-224", "MGF1", new DHGenParameterSpec(1024,160), PSource.PSpecified.DEFAULT));
    }

    @Test(expected = InvalidParameterSpecException.class)
    public void initSpecInvalidPSource() throws Exception {
        this.ap.init(new OAEPParameterSpec("SHA-224", "MGF1", new MGF1ParameterSpec("SHA-224"), new PSource("P") {}));
    }

    @Test(expected = IllegalArgumentException.class)
    public void initGetEncodedInvalidFormat() throws Exception {
        this.ap.init(new OAEPParameterSpec("SHA-1", "MGF1", MGF1ParameterSpec.SHA1, PSource.PSpecified.DEFAULT));
        byte[] encoded = this.ap.getEncoded("Invalid");
    }

    @Test(expected = IllegalArgumentException.class)
    public void initEncodedInvalidFormat() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"), "Invalid");
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidExplicitTagValue() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a21c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedMissingDigestAlgParamNull() throws Exception {
        this.ap.init(hexStringToByteArray("3042a00d300b0609608648016503040201a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidPssDigestOid() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165090402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidMgfOid() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a11c301a06092a864886f70d090108300d06096086480165030402020500a213301106092a864886f70d010109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidMgf1DigestOid() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165090402020500a213301106092a864886f70d010109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidPSourceOid() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d090109040401020304"));
    }

    @Test(expected = IOException.class)
    public void initEncodedInvalidPSpecified() throws Exception {
        this.ap.init(hexStringToByteArray("3044a00f300d06096086480165030402010500a11c301a06092a864886f70d010108300d06096086480165030402020500a213301106092a864886f70d010109060401020304"));
    }
}
