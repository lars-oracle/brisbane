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

import java.math.BigInteger;

public class InputChecks {

    private InputChecks() {}

    /**
     * Determines if any of the BigIntegers passed to this method is null or represents a zero or negative value.
     * @param bis zero or more potentially null BigIntegers
     * @return true if any of the BigIntegers is null or represents a zero or negative value
     */
    public static boolean isNullOrZeroOrNegative(BigInteger... bis) {
        if (bis == null) {
            return true;
        }
        for (BigInteger b : bis) {
            if (b == null || b.signum() <= 0) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines if any of the byte[]s passed to this method is null or encodes a zero or negative value.
     * @param bas zero or more byte[]'s each null or encoding a two's-complement representation of an Integer in
     *            big-endian byte-order without any redundant leading bytes.
     * @return true if any of the byte[]s is null or encodes a zero or negative value
     */
    public static boolean isNullOrZeroOrNegative(byte[]... bas) {
        if (bas == null) {
            return true;
        }
        for (byte[] ba : bas) {
            if (ba == null || (ba.length != 0 && ba[0] < 0) || (ba.length == 1 && ba[0] == 0)) {
                return true;
            }
        }
        return false;
    }

    /**
     * Determines if the non-null byte[] passed to this method is all zero bytes
     * @param ba a non-null byte array
     * @return true if the byte[] contains all zero bytes
     */
    public static boolean isAllZeros(byte[] ba) {
        // Constant-time (for a given byte array length) check for all zero bytes
        byte x = 0;
        for (byte b : ba) {
            x |= b;
        }
        return x == 0;
    }
}
