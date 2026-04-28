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

import org.junit.Assert;
import org.junit.Test;

import static org.junit.Assert.assertFalse;

public class UtilTest {

    static final char[] ONE_CHAR = new char[1];
    static final char[] TWO_CHAR = new char[2];
    static final char[] UNICODE_COFFEE = "coffee\u2615".toCharArray();
    static final byte[] UTF16_BE_ENCODED_COFFEE = new byte[]{0x00, 0x63, 0x00, 0x6f, 0x00, 0x66, 0x00, 0x66, 0x00, 0x65, 0x00, 0x65, 0x26, 0x15, 0x00, 0x00};

    @Test
    public void equalsCTNullTest1() {
        assertFalse(Util.equalsCT(null, ONE_CHAR));
    }

    @Test
    public void equalsCTNullTest2() {
        assertFalse(Util.equalsCT(ONE_CHAR, null));
    }

    @Test
    public void equalsCTLengthTest() {
        assertFalse(Util.equalsCT(ONE_CHAR, TWO_CHAR));
    }

    @Test
    public void equalsCTDiffValuesTest() {
        assertFalse(Util.equalsCT(new char[]{'a'}, new char[]{'b'}));
    }

    @Test(expected = IllegalArgumentException.class)
    public void hexToBytesInvalidLengthTest() {
        Util.hexToBytes("af1");
    }

    @Test
    public void clearNullArraysTest() {
        Util.clearArrays((byte[]) null);
    }

    @Test
    public void clearNullArrayTest() {
        Util.clearArray((long[]) null);
    }

    @Test
    public void utf16BeEncodeEmptyStringTest() {
        byte[] encoding = Util.utf16BeEncode(new char[0]);
        Assert.assertArrayEquals("Incorrect encoding", new byte[2], encoding);
    }

    @Test
    public void utf16BeEncodeNullTerminatedTest() {
        byte[] encoding = Util.utf16BeEncode(new char[1]);
        Assert.assertArrayEquals("Incorrect encoding", new byte[2], encoding);
    }

    @Test
    public void utf16BeEncodeNonAsciiTest() {
        byte[] encoding = Util.utf16BeEncode(UNICODE_COFFEE);
        Assert.assertArrayEquals("Incorrect encoding", UTF16_BE_ENCODED_COFFEE, encoding);
    }
}
