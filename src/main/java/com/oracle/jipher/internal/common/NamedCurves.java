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

import java.io.IOException;
import java.math.BigInteger;
import java.security.InvalidParameterException;
import java.security.spec.ECFieldFp;
import java.security.spec.ECGenParameterSpec;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;
import java.security.spec.EllipticCurve;
import java.util.HashMap;
import java.util.Map;

import com.oracle.jipher.internal.openssl.EcCurve;

/**
 * Helper class for handling conversions between supported named curve EcCurve, parameter specs and curve names
 */
public final class NamedCurves {

    private static final Map<String, ECParameterSpec> NAME_TO_SPEC;
    private static final Map<EcCurve, ECParameterSpec> CURVE_TO_SPEC;
    private static final Map<EcCurve, String> CURVE_TO_ENCODING;
    private static final Map<String, EcCurve> ENCODING_TO_CURVE;

    static {
        NAME_TO_SPEC = new HashMap<>();
        CURVE_TO_SPEC = new HashMap<>();
        CURVE_TO_ENCODING = new HashMap<>();
        ENCODING_TO_CURVE = new HashMap<>();
        addCurve("secp224r1", new String[]{"1.3.132.0.33", "P-224", "P224"}, EcCurve.secp224r1,
                "06052B81040021",
                createFpSpec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF000000000000000000000001",
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFFFFFFFFFFFFFFFFFE",
                        "B4050A850C04B3ABF54132565044B0B7D7BFD8BA270B39432355FFB4",
                        "B70E0CBD6BB4BF7F321390B94A03C1D356C21122343280D6115C1D21",
                        "BD376388B5F723FB4C22DFE6CD4375A05A07476444D5819985007E34",
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFF16A2E0B8F03E13DD29455C5C2A3D", 1));
        addCurve("secp256r1", new String[]{"1.2.840.10045.3.1.7", "P-256", "P256", "prime256v1"}, EcCurve.secp256r1,
                "06082A8648CE3D030107",
                createFpSpec("FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFF",
                        "FFFFFFFF00000001000000000000000000000000FFFFFFFFFFFFFFFFFFFFFFFC",
                        "5AC635D8AA3A93E7B3EBBD55769886BC651D06B0CC53B0F63BCE3C3E27D2604B",
                        "6B17D1F2E12C4247F8BCE6E563A440F277037D812DEB33A0F4A13945D898C296",
                        "4FE342E2FE1A7F9B8EE7EB4A7C0F9E162BCE33576B315ECECBB6406837BF51F5",
                        "FFFFFFFF00000000FFFFFFFFFFFFFFFFBCE6FAADA7179E84F3B9CAC2FC632551", 1));
        addCurve("secp384r1", new String[]{"1.3.132.0.34", "P-384", "P384"}, EcCurve.secp384r1,
                "06052B81040022",
                createFpSpec("FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFF",
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEFFFFFFFF0000000000000000FFFFFFFC",
                        "B3312FA7E23EE7E4988E056BE3F82D19181D9C6EFE8141120314088F5013875AC656398D8A2ED19D2A85C8EDD3EC2AEF",
                        "AA87CA22BE8B05378EB1C71EF320AD746E1D3B628BA79B9859F741E082542A385502F25DBF55296C3A545E3872760AB7",
                        "3617DE4A96262C6F5D9E98BF9292DC29F8F41DBD289A147CE9DA3113B5F0B8C00A60B1CE1D7E819D7A431D7C90EA0E5F",
                        "FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC7634D81F4372DDF581A0DB248B0A77AECEC196ACCC52973", 1));
        addCurve("secp521r1", new String[]{"1.3.132.0.35", "P-521", "P521"}, EcCurve.secp521r1,
                "06052B81040023",
                createFpSpec("01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFF",
                        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFC",
                        "0051953EB9618E1C9A1F929A21A0B68540EEA2DA725B99B315F3B8B489918EF109E156193951EC7E937B1652C0BD3BB1BF073573DF883D2C34F1EF451FD46B503F00",
                        "00C6858E06B70404E9CD9E3ECB662395B4429C648139053FB521F828AF606B4D3DBAA14B5E77EFE75928FE1DC127A2FFA8DE3348B3C1856A429BF97E7E31C2E5BD66",
                        "011839296A789A3BC0045C8A5FB42C7D1BD998F54449579B446817AFBD17273E662C97EE72995EF42640C550B9013FAD0761353C7086A272C24088BE94769FD16650",
                        "01FFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFA51868783BF2F966B7FCC0148F709A5D03BB5C9B8899C47AEBB6FB71E91386409", 1));
    }

    private static void addCurve(String curveName, String[] aliases, EcCurve curvId, String encodingHex, ECParameterSpec spec) {
        NAME_TO_SPEC.put(curveName.toLowerCase(), spec);
        for (String a : aliases) {
            NAME_TO_SPEC.put(a.toLowerCase(), spec);
        }
        CURVE_TO_SPEC.put(curvId, spec);
        CURVE_TO_ENCODING.put(curvId, encodingHex.toUpperCase());
        ENCODING_TO_CURVE.put(encodingHex.toUpperCase(), curvId);
    }

    private static ECParameterSpec createFpSpec(String p, String a, String b, String gx, String gy, String order, int cofactor) {
        return new ECParameterSpec(
                new EllipticCurve(
                        new ECFieldFp(new BigInteger(1, Util.hexToBytes(p))),
                        new BigInteger(1, Util.hexToBytes(a)),
                        new BigInteger(1, Util.hexToBytes(b))
                ),
                new ECPoint(
                        new BigInteger(1, Util.hexToBytes(gx)),
                        new BigInteger(1, Util.hexToBytes(gy))
                ),
                new BigInteger(1, Util.hexToBytes(order)),
                cofactor);
    }

    /**
     * Lookup a ECParameterSpec by the specified curve name.
     * @param curveName the curve name
     * @return the ECParameterSpec for the specified curve name
     */
    public static ECParameterSpec lookup(String curveName) {
        return NAME_TO_SPEC.get(curveName.toLowerCase());
    }

    /**
     * Lookup a ECParameterSpec by the EcCurve instance.
     * @param curve the curve
     * @return the ECParameterSpec for the specified curve name
     */
    public static ECParameterSpec lookup(EcCurve curve) {
        ECParameterSpec spec = CURVE_TO_SPEC.get(curve);
        if (spec == null) {
            throw new InvalidParameterException("Curve not supported.");
        }
        return spec;
    }

    /**
     * Returns the EcCurve represented by the given ECParameterSpec.
     * @param params curve parameters as ECParameterSpec
     * @return the EcCurve instance
     */
    public static EcCurve lookup(ECParameterSpec params) {
        for (Map.Entry<EcCurve, ECParameterSpec> entry : CURVE_TO_SPEC.entrySet()) {
            if (paramsEquals(entry.getValue(), params)) {
                return entry.getKey();
            }
        }
        return null;
    }

    /**
     * Returns the EcCurve represented by the given ECGenParameterSpec.
     * @param params curve parameters as ECGenParameterSpec
     * @return the EcCurve instance
     */
    public static EcCurve lookup(ECGenParameterSpec params) {
        ECParameterSpec spec = lookup(params.getName().toLowerCase());
        return lookup(spec);
    }

    /**
     * Returns a ECParameterSpec for the DER encoding, if encoding is of a supported curve.
     * @param encoding the DER encoded EC curve parameters
     * @return an ECParameterSpec
     * @throws IOException if the encoding is invalid, or represents an unsupported curve
     */
    public static ECParameterSpec decodeParams(byte[] encoding) throws IOException {
        EcCurve curve = ENCODING_TO_CURVE.get(Util.bytesToHex(encoding));
        if (curve == null) {
            throw new IOException("Unsupported encoded EC parameters.");
        }
        return lookup(curve);
    }

    /**
     * Returns the DER encoding of an ECParameterSpec, if it is a supported set of EC parameters.
     * @param spec the EC parameter spec
     * @return a DER encoding
     * @throws IOException for unsupported EC parameters, or problem encoding
     */
    public static byte[] getEncoded(ECParameterSpec spec) throws IOException {
        EcCurve curve = lookup(spec);
        if (curve == null) {
            throw new IOException("Unknown EC parameters, only named curve parameters supported.");
        }
        String encodingHex = CURVE_TO_ENCODING.get(curve);
        if (encodingHex == null) {
            // This should not happen.
            throw new IOException("Error encoding parameters.");
        }
        return Util.hexToBytes(encodingHex);
    }

    /**
     * Determines whether the specified ECParameterSpec objects represent the same
     * EC parameters.
     * @param spec1 the first spec to compare
     * @param spec2 the second spec to compare
     * @return true if the parameters contained in specs are equivalent. False otherwise
     */
    public static boolean paramsEquals(ECParameterSpec spec1, ECParameterSpec spec2) {
        if (spec1 == spec2) {
            return true;
        }
        if (spec1 == null || spec2 == null) {
            return false;
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
}
