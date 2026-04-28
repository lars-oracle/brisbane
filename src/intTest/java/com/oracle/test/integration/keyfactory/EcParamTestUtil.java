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

package com.oracle.test.integration.keyfactory;

import java.security.spec.ECFieldFp;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;

import com.oracle.jiphertest.helpers.CurveData;

import static com.oracle.jiphertest.helpers.EcParamSpecHelper.createSpec;
import static com.oracle.jiphertest.util.TestUtil.hexToBigInt;


public class EcParamTestUtil {

    public static final ECParameterSpec P224_PARAM_SPEC = createSpec(CurveData.P224_DATA);
    public static final ECParameterSpec P256_PARAM_SPEC = createSpec(CurveData.P256_DATA);
    public static final ECParameterSpec P384_PARAM_SPEC = createSpec(CurveData.P384_DATA);
    public static final ECParameterSpec P521_PARAM_SPEC = createSpec(CurveData.P521_DATA);

    public static ECParameterSpec get(String curve) {
        if ("secp256r1".equals(curve)) {
            return P256_PARAM_SPEC;
        }
        if ("secp224r1".equals(curve)) {
            return P224_PARAM_SPEC;
        }
        if ("secp384r1".equals(curve)) {
            return P384_PARAM_SPEC;
        }
        if ("secp521r1".equals(curve)) {
            return P521_PARAM_SPEC;
        }
        throw new Error("Curve not supported");
    }

    public static boolean paramsEquals(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == spec2) {
            return true;
        }
        if (!spec1.getCurve().equals(spec2.getCurve())) {
            return false;
        }
        if (!spec1.getGenerator().equals(spec2.getGenerator())) {
            return false;
        }
        if (!spec1.getOrder().equals(spec2.getOrder())) {
            return false;
        }
        return spec1.getCofactor() == spec2.getCofactor();
    }

    public static ECParameterSpec getUnsupported() {
        return new ECParameterSpec(
            new EllipticCurve(
                new ECFieldFp(hexToBigInt(CurveData.P256_DATA.primeHex)),
                hexToBigInt(CurveData.P256_DATA.aHex),
                hexToBigInt(CurveData.P256_DATA.bHex)
            ),
            new ECPoint(
                hexToBigInt(CurveData.P256_DATA.gyHex),
                hexToBigInt(CurveData.P256_DATA.gxHex)
            ),
            hexToBigInt(CurveData.P256_DATA.nHex),
            CurveData.P256_DATA.cofactor
        );
    }
}
