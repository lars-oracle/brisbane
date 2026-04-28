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

import java.io.Serial;
import java.math.BigInteger;
import java.security.spec.ECParameterSpec;
import java.security.spec.ECPoint;

/**
 * A collection of elliptic curve utility methods.
 */
public final class EcUtil {

    private static final int POINT_INFINITY = 0x00;
    private static final int UNCOMPRESSED = 0x04;

    private EcUtil() {
        // Do nothing
    }

    /**
     * Encode an EC point conforming to
     * <a href="https://www.secg.org/sec1-v2.pdf">SEC 1 Ver. 2.0</a> section 2.3.3.
     * Only the uncompressed point format is produced.
     *
     * @param point  the point to encode
     * @param params the ECParameterSpec
     * @return the encoded point
     */
    public static byte[] encodePointUncompressed(ECPoint point, ECParameterSpec params) {
        if (point.equals(ECPoint.POINT_INFINITY)) {
            return new byte[]{POINT_INFINITY};
        }

        byte[] x = point.getAffineX().toByteArray();
        int xLen = x.length;
        int xOffset = 0;
        byte[] y = point.getAffineY().toByteArray();
        int yLen = y.length;
        int yOffset = 0;

        // Strip leading zero from x, if any.
        if (xLen > 0 && x[0] == 0) {
            --xLen;
            ++xOffset;
        }

        // Strip leading zero from y, if any.
        if (yLen > 0 && y[0] == 0) {
            --yLen;
            ++yOffset;
        }

        // ceil(log2(q)/8) where q is the order of the field
        int fLen = (params.getCurve().getField().getFieldSize() + 7) / 8;
        byte[] encodedPoint = new byte[1 + fLen * 2];
        encodedPoint[0] = UNCOMPRESSED;
        System.arraycopy(x, xOffset, encodedPoint, encodedPoint.length - fLen - xLen, xLen);
        System.arraycopy(y, yOffset, encodedPoint, encodedPoint.length - yLen, yLen);
        return encodedPoint;
    }

    /**
     * Decode an uncompressed EC point encoding conforming to
     * <a href="https://www.secg.org/sec1-v2.pdf">SEC 1 Ver. 2.0</a> section 2.3.3.
     *
     * @param encodedPoint the uncompressed encoding of the EC point to decode
     * @return the decoded EC point
     */
    public static ECPoint decodePointUncompressed(byte[] encodedPoint) throws EcUtil.InvalidUncompressedECPoint {
        if ((encodedPoint.length == 1) && (encodedPoint[0] == POINT_INFINITY)) {
            return ECPoint.POINT_INFINITY;
        } else if (encodedPoint[0] == UNCOMPRESSED) {
            int coordinateLength = (encodedPoint.length - 1) / 2;
            BigInteger x = new BigInteger(1, encodedPoint, 1, coordinateLength);
            BigInteger y = new BigInteger(1, encodedPoint, 1 + coordinateLength, coordinateLength);
            return new ECPoint(x, y);
        } else {
            throw new EcUtil.InvalidUncompressedECPoint();
        }
    }

    public static class InvalidUncompressedECPoint extends Exception {
        @Serial
        private static final long serialVersionUID = -1048987106901698334L;
    }
}
