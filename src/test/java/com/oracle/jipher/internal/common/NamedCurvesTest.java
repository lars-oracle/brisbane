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

package com.oracle.jipher.internal.common;

import java.security.InvalidParameterException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.EllipticCurve;

import org.junit.Test;

import com.oracle.jipher.internal.openssl.EcCurve;
import com.oracle.jiphertest.helpers.CurveData;
import com.oracle.jiphertest.util.TestUtil;

import static com.oracle.jiphertest.helpers.EcParamSpecHelper.createSpec;
import static com.oracle.jiphertest.util.TestUtil.hexToBigInt;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;

public class NamedCurvesTest {

    void checkSpec(ECParameterSpec spec, CurveData curveData) {
        EllipticCurve curve = spec.getCurve();
        assertTrue(curve.getField() instanceof ECFieldFp);
        ECFieldFp fp = (ECFieldFp) curve.getField();
        assertEquals(hexToBigInt(curveData.primeHex), fp.getP());
        assertEquals(hexToBigInt(curveData.aHex), curve.getA());
        assertEquals(hexToBigInt(curveData.bHex), curve.getB());
        assertEquals(hexToBigInt(curveData.gxHex), spec.getGenerator().getAffineX());
        assertEquals(hexToBigInt(curveData.gyHex), spec.getGenerator().getAffineY());
        assertEquals(hexToBigInt(curveData.nHex), spec.getOrder());
        assertEquals(curveData.cofactor, spec.getCofactor());
    }

    @Test
    public void lookupByCurveP256() throws Exception {
        ECParameterSpec spec = NamedCurves.lookup(EcCurve.secp256r1);
        checkSpec(spec, CurveData.P256_DATA);
    }
    @Test
    public void lookupByCurveP224() throws Exception {
        ECParameterSpec spec = NamedCurves.lookup(EcCurve.secp224r1);
        checkSpec(spec, CurveData.P224_DATA);
    }
    @Test
    public void lookupByCurveP384() throws Exception {
        ECParameterSpec spec = NamedCurves.lookup(EcCurve.secp384r1);
        checkSpec(spec, CurveData.P384_DATA);
    }
    @Test
    public void lookupByCurveP521() throws Exception {
        ECParameterSpec spec = NamedCurves.lookup(EcCurve.secp521r1);
        checkSpec(spec, CurveData.P521_DATA);
    }

    @Test(expected = InvalidParameterException.class)
    public void lookupByCurveNull() throws Exception {
        ECParameterSpec spec = NamedCurves.lookup((EcCurve) null);
    }

    @Test
    public void lookupBySpec() throws Exception {
        ECParameterSpec spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertEquals(EcCurve.secp256r1, NamedCurves.lookup(spec));
    }

    @Test
    public void lookupBySpecNull() throws Exception {
        assertNull(NamedCurves.lookup((ECParameterSpec) null));
    }

    @Test
    public void lookupBySpecUnsupported() throws Exception {
        ECParameterSpec spec = createSpec("01" + CurveData.P256_DATA.nHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));

        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));

        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));


        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));

        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.nHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));

        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.primeHex, CurveData.P256_DATA.cofactor);
        assertNull(NamedCurves.lookup(spec));

        spec = createSpec(CurveData.P256_DATA.primeHex, CurveData.P256_DATA.aHex, CurveData.P256_DATA.bHex, CurveData.P256_DATA.gxHex, CurveData.P256_DATA.gyHex, CurveData.P256_DATA.nHex, 4);
        assertNull(NamedCurves.lookup(spec));
    }

    @Test
    public void lookupByName() throws Exception {
        checkSpec(NamedCurves.lookup("secp256r1"), CurveData.P256_DATA);
        checkSpec(NamedCurves.lookup("P-256"), CurveData.P256_DATA);
        checkSpec(NamedCurves.lookup("prime256v1"), CurveData.P256_DATA);
        checkSpec(NamedCurves.lookup("1.2.840.10045.3.1.7"), CurveData.P256_DATA);

        checkSpec(NamedCurves.lookup("secp224r1"), CurveData.P224_DATA);
        checkSpec(NamedCurves.lookup("P-224"), CurveData.P224_DATA);
        checkSpec(NamedCurves.lookup("1.3.132.0.33"), CurveData.P224_DATA);

        checkSpec(NamedCurves.lookup("secp384r1"), CurveData.P384_DATA);
        checkSpec(NamedCurves.lookup("P-384"), CurveData.P384_DATA);
        checkSpec(NamedCurves.lookup("1.3.132.0.34"), CurveData.P384_DATA);

        checkSpec(NamedCurves.lookup("secp521r1"), CurveData.P521_DATA);
        checkSpec(NamedCurves.lookup("P-521"), CurveData.P521_DATA);
        checkSpec(NamedCurves.lookup("1.3.132.0.35"), CurveData.P521_DATA);
    }

    @Test
    public void getEncoded() throws Exception {
        assertArrayEquals(TestUtil.hexStringToByteArray("06052B81040021"), NamedCurves.getEncoded(createSpec(CurveData.P224_DATA)));
        assertArrayEquals(TestUtil.hexStringToByteArray("06082A8648CE3D030107"), NamedCurves.getEncoded(createSpec(CurveData.P256_DATA)));
        assertArrayEquals(TestUtil.hexStringToByteArray("06052B81040022"), NamedCurves.getEncoded(createSpec(CurveData.P384_DATA)));
        assertArrayEquals(TestUtil.hexStringToByteArray("06052B81040023"), NamedCurves.getEncoded(createSpec(CurveData.P521_DATA)));
    }

    @Test
    public void decode() throws Exception {
        checkSpec(NamedCurves.decodeParams(TestUtil.hexStringToByteArray("06052B81040021")), CurveData.P224_DATA);
        checkSpec(NamedCurves.decodeParams(TestUtil.hexStringToByteArray("06082A8648CE3D030107")), CurveData.P256_DATA);
        checkSpec(NamedCurves.decodeParams(TestUtil.hexStringToByteArray("06052B81040022")), CurveData.P384_DATA);
        checkSpec(NamedCurves.decodeParams(TestUtil.hexStringToByteArray("06052B81040023")), CurveData.P521_DATA);
    }


}
