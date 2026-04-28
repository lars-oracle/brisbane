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

package com.oracle.jipher.internal.asn1;

public enum UniversalTag {
    BOOLEAN(1),
    INTEGER(2),
    BIT_STRING(3),
    OCTET_STRING(4),
    NULL(5),
    OBJECT_IDENTIFIER(6),
    ENUMERATED(10),
    RELATIVE_OID(13),
    SEQUENCE(16),
    SET(17),

    // Restricted Character String
    UTF8String(12),
    NumericString(18),
    PrintableString(19),
    TeletexString(20),
    T61String(20), // Same as TeletexString
    VideotexString(21),
    IA5String(22),
    GraphicString(25),
    VisibleString(26),
    ISO646String(26), // Same as VisibleString
    GeneralString(27),
    UniversalString(28),
    BMPString(30),

    // "useful types"
    UTCTime(23),
    GeneralizedTime(24);

    public final int tagValue;
    UniversalTag(int tagValue) {
        this.tagValue = tagValue;
    }
    public String asn1Name() {
        return name().replace('_', ' ');
    }
}
