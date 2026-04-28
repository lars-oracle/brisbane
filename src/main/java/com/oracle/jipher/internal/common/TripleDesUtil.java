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

import java.nio.ByteBuffer;
import java.security.InvalidKeyException;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;


/**
 * A collection of TripleDES-related utility methods.
 */
public final class TripleDesUtil {

    private static final int NUM_KEY_BYTES = 24;

    private static final long[] WEAK_KEYS = {
        // From NIST SP 800-67, Revision 2
        // Weak keys
        0x0101010101010101L,
        0xfefefefefefefefeL,
        0xe0e0e0e0f1f1f1f1L,
        0x1f1f1f1f0e0e0e0eL,

        // Semi-weak keys
        0x011f011f010e010eL,
        0x1f011f010e010e01L,
        0x01e001e001f101f1L,
        0xe001e001f101f101L,
        0x01fe01fe01fe01feL,
        0xfe01fe01fe01fe01L,
        0x1fe01fe00ef10ef1L,
        0xe01fe01ff10ef10eL,
        0x1ffe1ffe0efe0efeL,
        0xfe1ffe1ffe0efe0eL,
        0xe0fee0fef1fef1feL,
        0xfee0fee0fef1fef1L,

        // Possibly-weak keys
        0x01011f1f01010e0eL,
        0x1f1f01010e0e0101L,
        0xe0e01f1ff1f10e0eL,
        0x0101e0e00101f1f1L,
        0x1f1fe0e00e0ef1f1L,
        0xe0e0fefef1f1fefeL,
        0x0101fefe0101fefeL,
        0x1f1ffefe0e0efefeL,
        0xe0fe011ff1fe010eL,
        0x011f1f01010e0e01L,
        0x1fe001fe0ef101feL,
        0xe0fe1f01f1fe0e01L,
        0x011fe0fe010ef1feL,
        0x1fe0e01f0ef1f10eL,
        0xe0fefee0f1fefef1L,
        0x011ffee0010efef1L,
        0x1fe0fe010ef1fe01L,
        0xfe0101fefe0101feL,
        0x01e01ffe01f10efeL,
        0x1ffe01e00efe01f1L,
        0xfe011fe0fe010ef1L,
        0xfe01e01ffe01f10eL,
        0x1ffee0010efef101L,
        0xfe1f01e0fe0e01f1L,
        0x01e0e00101f1f101L,
        0x1ffefe1f0efefe0eL,
        0xfe1fe001fe0ef101L,
        0x01e0fe1f01f1fe0eL,
        0xe00101e0f10101f1L,
        0xfe1f1ffefe0e0efeL,
        0x01fe1fe001fe0ef1L,
        0xe0011ffef1010efeL,
        0xfee0011ffef1010eL,
        0x01fee01f01fef10eL,
        0xe001fe1ff101fe0eL,
        0xfee01f01fef10e01L,
        0x01fefe0101fefe01L,
        0xe01f01fef10e01feL,
        0xfee0e0fefef1f1feL,
        0x1f01011f0e01010eL,
        0xe01f1fe0f10e0ef1L,
        0xfefe0101fefe0101L,
        0x1f01e0fe0e01f1feL,
        0xe01ffe01f10efe01L,
        0xfefe1f1ffefe0e0eL,
        0x1f01fee00e01fef1L,
        0xe0e00101f1f10101L,
        0xfefee0e0fefef1f1L
    };

    private static final byte[] PARITY_TABLE = genParityTable();

    private TripleDesUtil() {
        // Do nothing
    }

    private static byte[] genParityTable() {
        byte[] tbl = new byte[128];
        for (int i = 0; i < tbl.length; ++i) {
            tbl[i] = (byte)((i << 1) | (Integer.bitCount(i) & 1 ^ 1));
        }
        return tbl;
    }

    public static void setParityBits(byte[] key) {
        for (int i = 0; i < key.length; ++i) {
            key[i] = PARITY_TABLE[(key[i] >>> 1) & 0x7f];
        }
    }

    static boolean isWeakKey(long[] subKeys) {
        for (long subKey: subKeys) {
            if (isWeakKey(subKey)) {
                return true;
            }
        }
        return false;
    }

    private static boolean isWeakKey(long key) {
        for (long wk: WEAK_KEYS) {
            if (key == wk) {
                return true;
            }
        }
        return false;
    }

    private static boolean isWeakKeyBytes(byte[] keyBytes) {
        long[] subKeys = new long[3];

        try {
            ByteBuffer.wrap(keyBytes).asLongBuffer().get(subKeys);
            // Check for duplicate sub-keys
            if (subKeys[0] == subKeys[1] || subKeys[0] == subKeys[2] || subKeys[1] == subKeys[2]) {
                return true;
            }
            return isWeakKey(subKeys);
        } finally {
            Util.clearArray(subKeys);
        }
    }

    public static SecretKey createKey(byte[] keyMaterial) throws InvalidKeyException {
        if (keyMaterial == null || keyMaterial.length < NUM_KEY_BYTES) {
            throw new InvalidKeyException("Insufficient Key material");
        }

        byte[] keyBytes = Arrays.copyOfRange(keyMaterial, 0, NUM_KEY_BYTES);
        try {
            setParityBits(keyBytes);
            if (isWeakKeyBytes(keyBytes)) {
                throw new InvalidKeyException("Weak key material");
            }
            return new SecretKeySpec(keyBytes, "DESede");
        } finally {
            Util.clearArray(keyBytes);
        }
    }
}
