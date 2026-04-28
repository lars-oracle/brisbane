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

package com.oracle.jiphertest.util;

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.util.Arrays;
import java.util.Random;

/**
 * Utility methods for use in test classes.
 */
public class TestUtil {

    public static byte[] randomBytes(int len) {
        byte[] bb = new byte[len];
        Random r = new Random();
        r.nextBytes(bb);
        return bb;
    }

    public static byte[] concat(byte[]...arr) {
        int len = 0;
        for (byte[] bb : arr) {
            if (bb != null) {
                len += bb.length;
            }
        }
        byte[] ret = new byte[len];
        int offs = 0;
        for (byte[] bb : arr) {
            if (bb != null) {
                System.arraycopy(bb, 0, ret, offs, bb.length);
                offs += bb.length;
            }
        }
        return ret;
    }

    public static BigInteger hexToBigInt(String hex) {
        return new BigInteger(1, hexStringToByteArray(hex));
    }

    /**
     * Converts a hexadecimal string to a byte array.
     *
     * @param hexString a hexadecimal string
     * @return a byte array representation of the hex string
     */
    public static byte[] hexStringToByteArray(String hexString) {
        byte[] bytes = new byte[hexString.length() / 2];
        for (int i = 0; i < bytes.length; ++i) {
            bytes[i] = (byte) (Character.digit(hexString.charAt(i * 2), 16) << 4 |
                    Character.digit(hexString.charAt(i * 2 + 1), 16));
        }
        return bytes;
    }

    private final static char[] HEX_ARRAY = "0123456789ABCDEF".toCharArray();

    public static String bytesToHex(byte[] bytes) {
        return bytesToHex(bytes, bytes.length);
    }

    public static String bytesToHex(byte[] bytes, int len) {
        char[] hexChars = new char[len * 2];
        for (int j = 0; j < len; j++) {
            int v = bytes[j] & 0xFF;
            hexChars[j * 2] = HEX_ARRAY[v >>> 4];
            hexChars[j * 2 + 1] = HEX_ARRAY[v & 0x0F];
        }
        return new String(hexChars);
    }


    public static byte[] hexToBytes(String hex) {
        int len = hex.length();
        if (len % 2 != 0) {
            throw new IllegalArgumentException("Hex string should contain even number of characters");
        }
        byte[] bytes = new byte[len / 2];
        for (int i = 0; i < len; i += 2) {
            bytes[i / 2] = (byte) ((Character.digit(hex.charAt(i), 16) << 4)
                    + Character.digit(hex.charAt(i + 1), 16));
        }
        return bytes;
    }

    private static String hexString(int value, int padding) {
        String hexString = "0123456789ABCDEF";
        StringBuffer tempString = new StringBuffer(
                "                                                                              ".substring(0, padding));
        int offset = padding - 1;

        for (int i = 0; i < padding; i++) {
            tempString.setCharAt(offset - i,
                    hexString.charAt(value >> i * 4 & 0xF));
        }
        return tempString.toString();
    }

    public static ByteBuffer directByteBuffer(byte[] bytes) {
        ByteBuffer bb = ByteBuffer.allocateDirect(bytes.length);
        bb.put(bytes);
        bb.rewind();
        return bb;
    }

    /**
     * Trims leading zeros from a byte[]
     */
    public static byte[] trimLeadingZeros(byte[] input) {
        if (input == null) {
            return null;
        }
        int idx = 0;
        while ((idx < input.length) && (input[idx] == 0)) {
            idx++;
        }

        return Arrays.copyOfRange(input, idx, input.length);
    }
}
