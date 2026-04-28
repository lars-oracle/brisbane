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

import java.math.BigInteger;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import org.junit.After;
import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;

public class OsslParamTest {

    OpenSsl openSsl;
    OsslArena testArena;

    @Before
    public void setUp() throws Exception {
        openSsl = OpenSsl.getInstance();
        testArena = OsslArena.ofConfined();
    }

    @After
    public void tearDown() throws Exception {
        testArena.close();
    }

    @Test
    public void storeLoad() {
        String _string = "test";
        byte[] stringBytes = _string.getBytes(StandardCharsets.UTF_8);
        BigInteger bigInteger = new BigInteger("1000000000000000000000000000000000000000000000000001");
        byte[] octetString = "octets".getBytes();

        List<OSSL_PARAM> paramList = new ArrayList<>();
        paramList.add(OSSL_PARAM.ofIntegerBytes("short", ByteBuffer.allocate(Short.BYTES).putShort(Short.MAX_VALUE).array()));
        paramList.add(OSSL_PARAM.of("integer", Integer.MAX_VALUE));
        paramList.add(OSSL_PARAM.of("long", Long.MAX_VALUE));
        paramList.add(OSSL_PARAM.of("float", Float.MAX_VALUE));
        paramList.add(OSSL_PARAM.of("double", Double.MAX_VALUE));
        paramList.add(OSSL_PARAM.of("string",  _string));
        paramList.add(OSSL_PARAM.of("octet string", octetString));
        paramList.add(OSSL_PARAM.of("big integer", bigInteger));

        paramList.add(OSSL_PARAM.ofUnsigned("unsigned integer", Integer.MAX_VALUE));
        paramList.add(OSSL_PARAM.ofUnsigned("unsigned long", Long.MAX_VALUE));
        paramList.add(OSSL_PARAM.ofUnsigned("unsigned big integer", bigInteger));
        paramList.add(OSSL_PARAM.ofUnsignedIntegerBytes("unsigned big integer from bytes", bigInteger.toByteArray()));

        paramList.add(OSSL_PARAM.ofUnsigned("wrapped unsigned integer", -1));
        paramList.add(OSSL_PARAM.ofUnsigned("wrapped unsigned long", -1L));

        OsslParamBuffer ossParamBuffer = this.openSsl.dataParamBuffer(this.testArena, paramList.toArray(OSSL_PARAM.EMPTY_ARRAY));

        assertTrue(ossParamBuffer.locate("short").isPresent());
        assertEquals(Short.MAX_VALUE, ossParamBuffer.locate("short").get().intValue());
        assertTrue(ossParamBuffer.locate("integer").isPresent());
        assertEquals(Integer.MAX_VALUE, ossParamBuffer.locate("integer").get().intValue());
        assertEquals(Integer.MAX_VALUE, ossParamBuffer.locate("integer").get().intValueExact());
        assertTrue(ossParamBuffer.locate("long").isPresent());
        assertEquals(Long.MAX_VALUE, ossParamBuffer.locate("long").get().longValue());
        assertEquals(Long.MAX_VALUE, ossParamBuffer.locate("long").get().longValueExact());
        assertTrue(ossParamBuffer.locate("float").isPresent());
        assertEquals(Float.MAX_VALUE, ossParamBuffer.locate("float").get().floatValue(), 0.0F);
        assertTrue(ossParamBuffer.locate("double").isPresent());
        assertEquals(Double.MAX_VALUE, ossParamBuffer.locate("double").get().doubleValue(), 0.0F);
        assertTrue(ossParamBuffer.locate("string").isPresent());
        OSSL_PARAM stringParam = ossParamBuffer.locate("string").get();
        assertArrayEquals(_string.getBytes(StandardCharsets.UTF_8), stringParam.data);
        assertEquals(_string, stringParam.stringValue());
        assertTrue(ossParamBuffer.locate("octet string").isPresent());
        OSSL_PARAM octetStringParam = ossParamBuffer.locate("octet string").get();
        assertArrayEquals(octetString, octetStringParam.data);
        assertArrayEquals(octetString, octetStringParam.byteArrayValue());
        assertTrue(ossParamBuffer.locate("big integer").isPresent());
        OSSL_PARAM bigIntegerParam = ossParamBuffer.locate("big integer").get();
        assertArrayEquals(bigInteger.toByteArray(), bigIntegerParam.data);
        assertEquals(bigInteger, bigIntegerParam.bigIntegerValue());

        assertTrue(ossParamBuffer.locate("unsigned integer").isPresent());
        assertEquals(Integer.MAX_VALUE, ossParamBuffer.locate("unsigned integer").get().intValue());
        assertTrue(ossParamBuffer.locate("unsigned long").isPresent());
        assertEquals(Long.MAX_VALUE, ossParamBuffer.locate("unsigned long").get().longValue());
        assertTrue(ossParamBuffer.locate("unsigned big integer").isPresent());
        assertEquals(bigInteger, ossParamBuffer.locate("unsigned big integer").get().bigIntegerValue());
        assertTrue(ossParamBuffer.locate("unsigned big integer from bytes").isPresent());
        OSSL_PARAM unsignedBigIntegerFromBytesParam = ossParamBuffer.locate("unsigned big integer from bytes").get();
        assertArrayEquals(bigInteger.toByteArray(), unsignedBigIntegerFromBytesParam.data);
        assertEquals(bigInteger, unsignedBigIntegerFromBytesParam.bigIntegerValue());

        assertTrue(ossParamBuffer.locate("wrapped unsigned integer").isPresent());
        assertEquals(-1, ossParamBuffer.locate("wrapped unsigned integer").get().intValue());
        assertTrue(ossParamBuffer.locate("wrapped unsigned long").isPresent());
        assertEquals(-1L, ossParamBuffer.locate("wrapped unsigned long").get().longValue());
    }

    @Test
    public void index() {
        List<OSSL_PARAM> params = new ArrayList<>();
        for (int i = 0; i < 3; i++) {
            params.add(OSSL_PARAM.of("key" + i, "value" + i));
        }
        OsslParamBuffer ossParamBuffer = this.openSsl.dataParamBuffer(this.testArena, params.toArray(OSSL_PARAM.EMPTY_ARRAY));
        for (int i = 0; i < 3; i++) {
            OSSL_PARAM param = ossParamBuffer.get(i);
            assertEquals("key" + i, param.key);
            assertEquals("value" + i, param.stringValue());
        }
    }

    @Test
    public void testIgnoreNullParams() {
        OsslParamBuffer ossParamBuffer = this.openSsl.dataParamBuffer(this.testArena,
                OSSL_PARAM.of("int1", 1),
                null,
                OSSL_PARAM.of("int3", 3),
                null,
                OSSL_PARAM.of("int5", 5));

        assertEquals(3, ossParamBuffer.count());
        for (int i = 0; i < 3; i++) {
            OSSL_PARAM param = ossParamBuffer.get(i);
            int n = i * 2 + 1;
            assertEquals("int" + n, param.key);
            assertEquals(n, param.intValueExact());
        }
    }

    @Test
    public void testToStringUtf8String() {
        OSSL_PARAM param = OSSL_PARAM.of("key", "data");
        assertEquals("key:key data_type:UTF8_STRING data_size:4 data:\"data\" return_size:-1",  param.toString());
    }

    @Test
    public void testToStringUtf8Ptr() {
        OSSL_PARAM param = new OSSL_PARAM("key", OSSL_PARAM.Type.UTF8_PTR, "data".getBytes(StandardCharsets.UTF_8), 0L, 4L, false);
        assertEquals("key:key data_type:UTF8_PTR data_size:0 data:\"data\" return_size:4", param.toString());
    }

    @Test
    public void testToStringUtf8PtrNoData() {
        OSSL_PARAM param = OSSL_PARAM.of("key", OSSL_PARAM.Type.UTF8_PTR);
        assertEquals("key:key data_type:UTF8_PTR data_size:0 data:null return_size:-1",  param.toString());
    }

    @Test
    public void realWithSize() {
        OSSL_PARAM real4 = OSSL_PARAM.of("key", OSSL_PARAM.Type.REAL, 4);
        assertEquals(4, real4.dataSize);

        OSSL_PARAM real8 = OSSL_PARAM.of("key", OSSL_PARAM.Type.REAL, 8);
        assertEquals(8, real8.dataSize);
    }

    @Test
    public void utf8PtrWithNonZeroSize() {
        OSSL_PARAM utf8Ptr = OSSL_PARAM.of("key", OSSL_PARAM.Type.UTF8_PTR, 1);
        assertEquals(OSSL_PARAM.Type.UTF8_PTR, utf8Ptr.dataType);
        assertEquals(1, utf8Ptr.dataSize);
    }

    @Test
    public void utf8PtrWithZeroSize() {
        OSSL_PARAM utf8Ptr = OSSL_PARAM.of("key", OSSL_PARAM.Type.UTF8_PTR, 0);
        assertEquals(OSSL_PARAM.Type.UTF8_PTR, utf8Ptr.dataType);
        assertEquals(0, utf8Ptr.dataSize);
    }

    @Test
    public void octetPtrWithNonZeroSize() {
        OSSL_PARAM utf8Ptr = OSSL_PARAM.of("key", OSSL_PARAM.Type.OCTET_PTR, 1);
        assertEquals(OSSL_PARAM.Type.OCTET_PTR, utf8Ptr.dataType);
        assertEquals(1, utf8Ptr.dataSize);
    }

    @Test
    public void octetPtrWithZeroSize() {
        OSSL_PARAM utf8Ptr = OSSL_PARAM.of("key", OSSL_PARAM.Type.OCTET_PTR, 0);
        assertEquals(OSSL_PARAM.Type.OCTET_PTR, utf8Ptr.dataType);
        assertEquals(0, utf8Ptr.dataSize);
    }

    @Test
    public void octetStringWithNonZeroSize() {
        OSSL_PARAM octetString = OSSL_PARAM.of("key", OSSL_PARAM.Type.OCTET_STRING, 1);
        assertEquals(OSSL_PARAM.Type.OCTET_STRING, octetString.dataType);
        assertEquals(1, octetString.dataSize);
    }

    @Test
    public void octetPtrByteArrayValue() {
        byte[] octetString = "octets".getBytes();
        OSSL_PARAM param = new OSSL_PARAM("octet ptr", OSSL_PARAM.Type.OCTET_PTR, octetString);
        assertArrayEquals(octetString, param.byteArrayValue());
    }

    @Test
    public void clearSensitiveData() {
        BigInteger bigInteger = new BigInteger("77777777777777777777777777777777777");
        byte[] bigIntegerBytes = bigInteger.toByteArray();
        OSSL_PARAM param = OSSL_PARAM.ofUnsignedIntegerBytes("key", bigIntegerBytes);
        assertArrayEquals(bigInteger.toByteArray(), param.byteArrayValue());

        // The internal data byte array is the same byte array as was passed to OSSL_PARAM::ofUnsignedIntegerBytes.
        assertSame(bigIntegerBytes, param.data);

        byte[] zeroBuffer = new byte[bigIntegerBytes.length];
        assertFalse(Arrays.equals(bigIntegerBytes, zeroBuffer));

        // Clear the internal data buffer.
        assertFalse(param.isDestroyed());
        param.destroy();
        assertTrue(param.isDestroyed());

        // Verify that the internal data byte array was cleared.
        assertArrayEquals(zeroBuffer, param.data);

        // The byte array that was passed to OSSL_PARAM::ofUnsignedIntegerBytes was also cleared as it is the same buffer.
        assertArrayEquals(zeroBuffer, bigIntegerBytes);
    }

    @Test
    public void destroyOsslParamArray() {
        byte[] bitInterOneBytes = BigInteger.ONE.toByteArray();
        byte[] bitInterTwoBytes = BigInteger.TWO.toByteArray();

        OSSL_PARAM[] params = new OSSL_PARAM[]{
                OSSL_PARAM.ofUnsignedIntegerBytes("one", bitInterOneBytes),
                OSSL_PARAM.ofUnsignedIntegerBytes("two", bitInterTwoBytes)
        };

        // Destroy both parameters
        OSSL_PARAM.destroy(params);

        // Verify that the parameters have been destroyed
        for (OSSL_PARAM param : params) {
            assertTrue(param.isDestroyed());
        }

        // Verify that the internal data byte arrays were cleared.
        assertArrayEquals(new byte[bitInterOneBytes.length], bitInterOneBytes);
        assertArrayEquals(new byte[bitInterTwoBytes.length], bitInterTwoBytes);
    }

    @Test
    public void sensitiveParam() {
        BigInteger bigInteger = new BigInteger("77777777777777777777777777777777777");
        byte[] bigIntegerBytes = bigInteger.toByteArray();
        OSSL_PARAM sensitiveParam = OSSL_PARAM.ofUnsignedIntegerBytes("sensitive", bigIntegerBytes).sensitive();
        OsslParamBuffer ossParamBuffer = this.openSsl.dataParamBuffer(this.testArena, sensitiveParam);
        OSSL_PARAM intParam = ossParamBuffer.locate("sensitive").get();
        assertEquals("sensitive", intParam.key);
        assertEquals(OSSL_PARAM.Type.UNSIGNED_INTEGER, intParam.dataType);
        assertEquals(bigInteger, intParam.bigIntegerValue());
        assertEquals(bigIntegerBytes.length, intParam.dataSize);
        assertEquals(OSSL_PARAM.PARAM_UNMODIFIED, intParam.returnSize);
        assertFalse(intParam.sensitive); // sensitive is always false for loaded params.
    }

    @Test
    public void intValueExact()
    {
        int i = Integer.MAX_VALUE;
        assertEquals(i, OSSL_PARAM.of("number", i).intValueExact());
        assertEquals(i, OSSL_PARAM.of("number", (long) i).intValueExact());
        assertEquals(i, OSSL_PARAM.of("number", BigInteger.valueOf(i)).intValueExact());
    }

    @Test
    public void longValueExact()
    {
        int i = Integer.MAX_VALUE;
        long l = Long.MAX_VALUE;
        assertEquals(i, OSSL_PARAM.of("number", i).longValueExact());
        assertEquals(l, OSSL_PARAM.of("number", l).longValueExact());
        assertEquals(l, OSSL_PARAM.of("number", BigInteger.valueOf(l)).longValueExact());
    }

    @Test
    public void loadIntegerType() {
        OSSL_PARAM integerTemplate = OSSL_PARAM.of("integer", OSSL_PARAM.Type.INTEGER);
        OsslParamBuffer osslParamBuffer = this.openSsl.templateParamBuffer(this.testArena, integerTemplate);
        OSSL_PARAM integerParam = osslParamBuffer.locate("integer").get();
        assertEquals("integer", integerParam.key);
        assertEquals(OSSL_PARAM.Type.INTEGER, integerParam.dataType);
        assertNull(integerParam.data);
        assertEquals(Integer.BYTES, integerParam.dataSize);
        assertEquals(OSSL_PARAM.PARAM_UNMODIFIED, integerParam.returnSize);
    }

    // Negative tests

    @Test (expected = NullPointerException.class)
    public void nullKeyNeg() {
        OSSL_PARAM.of(null, OSSL_PARAM.Type.INTEGER);
    }

    @Test (expected = IllegalStateException.class)
    public void noDataIntValue() {
        OSSL_PARAM.of("key", OSSL_PARAM.Type.INTEGER).intValue();
    }

    @Test (expected = IllegalArgumentException.class)
    public void negativeDataSizeNeg() {
        OSSL_PARAM.of("key", OSSL_PARAM.Type.NONE, -1);
    }

    @Test (expected = IllegalStateException.class)
    public void invalidIntegerNeg() {
        OSSL_PARAM.of("key", "value").intValue();
    }

    @Test (expected = IllegalStateException.class)
    public void invalidLongNeg() {
        OSSL_PARAM.of("key", "value").longValue();
    }

    @Test (expected = IllegalStateException.class)
    public void invalidFloatNeg() {
        OSSL_PARAM.of("key", "value").floatValue();
    }

    @Test (expected = IllegalStateException.class)
    public void invalidDoubleNeg() {
        OSSL_PARAM.of("key", "value").doubleValue();
    }

    @Test (expected = IllegalStateException.class)
    public void invalidBigIntegerNeg() {
        OSSL_PARAM.of("key", "value").bigIntegerValue();
    }

    @Test (expected = IllegalStateException.class)
    public void invalidStringNeg() {
        OSSL_PARAM.of("key", 1).stringValue();
    }

    @Test (expected = IllegalArgumentException.class)
    public void invalidUnsignedBigIntegerNeg() {
        OSSL_PARAM.ofUnsigned("key", new BigInteger("-1"));
    }

    @Test (expected = IllegalArgumentException.class)
    public void octetStringWithZeroSizeNeg() {
        OSSL_PARAM octetString = OSSL_PARAM.of("key", OSSL_PARAM.Type.OCTET_STRING, 0);
    }

    @Test (expected = IllegalArgumentException.class)
    public void invalidRealWithSizeNeg() {
        OSSL_PARAM.of("real", OSSL_PARAM.Type.REAL, 3);
    }

    @Test
    public void intValueExactOverflowNeg()
    {
        OSSL_PARAM param;

        param = OSSL_PARAM.of("number", Integer.MAX_VALUE + 1L);
        try {
            param.intValueExact();
            Assert.fail("Should have thrown an ArithmeticException(\"integer overflow\")");
        } catch (ArithmeticException e) {
            // Expected Exception
        }

        param = OSSL_PARAM.of("number", BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE));
        try {
            param.intValueExact();
            Assert.fail("Should have thrown an ArithmeticException(\"BigInteger out of int range\")");
        } catch (ArithmeticException e) {
            // Expected Exception
        }
    }

    @Test
    public void intValueExactNotIntegerNeg()
    {
        OSSL_PARAM param;

        param = OSSL_PARAM.of("number", Float.MAX_VALUE);
        try {
            param.intValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }

        param = OSSL_PARAM.of("number", Double.MAX_VALUE);
        try {
            param.intValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }

        param = OSSL_PARAM.of("string", "test");
        try {
            param.intValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }
    }

    @Test
    public void longValueExactOverflowNeg()
    {
        BigInteger b = BigInteger.valueOf(Long.MAX_VALUE).add(BigInteger.ONE);

        OSSL_PARAM param = OSSL_PARAM.of("number", b);
        try {
            param.longValueExact();
            Assert.fail("Should have thrown an ArithmeticException(\"BigInteger out of long range\")");
        } catch (ArithmeticException e) {
            // Expected Exception
        }
    }

    @Test
    public void longValueExactNotIntegerNeg()
    {
        OSSL_PARAM param;

        param = OSSL_PARAM.of("number", Float.MAX_VALUE);
        try {
            param.longValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }

        param = OSSL_PARAM.of("number", Double.MAX_VALUE);
        try {
            param.longValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }

        param = OSSL_PARAM.of("string", "test");
        try {
            param.longValueExact();
            Assert.fail("Should have thrown an IllegalStateException(\"Not INTEGER or UNSIGNED_INTEGER\")");
        } catch (IllegalStateException e) {
            // Expected Exception
        }
    }
}
