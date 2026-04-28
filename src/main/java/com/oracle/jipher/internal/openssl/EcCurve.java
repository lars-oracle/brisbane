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

package com.oracle.jipher.internal.openssl;

/**
 * Enum for supported named Elliptic Curves
 */
public enum EcCurve {
    secp224r1("secp224r1", "1.3.132.0.33", 224),
    secp256r1("prime256v1", "1.2.840.10045.3.1.7", 256), // NID_X9_62_prime256v1, secp256r1
    secp384r1("secp384r1", "1.3.132.0.34", 384),
    secp521r1("secp521r1", "1.3.132.0.35", 521);

    private final String sn;
    private final String oid;
    private final int keyBits;

    EcCurve(String sn, String oid, int keyBits) {
        this.sn = sn;
        this.oid = oid;
        this.keyBits = keyBits;
    }

    /**
     * Gets the OpenSSL Short Name for the curve.
     *  @return the curve OpenSSL Short Name as a String
     */
    public String sn() {
        return this.sn;
    }

    /**
     * Gets the OID for the curve.
     *  @return the curve OID as a String
     */
    public String oid() {
        return this.oid;
    }

    /**
     * Returns the key bits strength associated with this curve.
     *  @return the key bits of strength
     */
    public int keyBits() {
        return this.keyBits;
    }

    /**
     * Returns the EcCurve that has the specified OpenSSL short name.
     *  @param sn the OpenSSL short name of the curve to return
     *  @return the EcCurve
     */
    public static EcCurve bySn(String sn) {
        for (EcCurve c : values()) {
            if (c.sn.equals(sn)) {
                return c;
            }
        }
        return null;
    }
}
