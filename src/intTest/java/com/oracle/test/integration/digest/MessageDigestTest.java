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

package com.oracle.test.integration.digest;

import java.security.MessageDigest;
import java.util.Arrays;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.DataSize;
import com.oracle.jiphertest.testdata.DigestTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.alg;

/**
 * MessageDigest API tests for general message digest implementation.
 * <p>
 * This test class aims to ensure all APIs are working correctly, but does not
 * test individual algorithm behavior.
 */
public class MessageDigestTest {

    //"The quick brown fox jumps over the lazy dog"
    private String alg;
    private byte[] data;
    private byte[] dataDigest;
    private byte[] emptyDigest;

    MessageDigest md;

    @Before
    public void setUp() throws Exception {
        alg = "SHA-256";
        DigestTestVector tv = TestData.getFirst(DigestTestVector.class, alg(alg).dataSize(DataSize.BASIC));
        DigestTestVector tvEmpty = TestData.getFirst(DigestTestVector.class, alg(alg).dataSize(DataSize.EMPTY));
        data = tv.getData();
        dataDigest = tv.getDigest();
        emptyDigest = tvEmpty.getDigest();
        md = ProviderUtil.getMessageDigest(alg);
    }

    @Test
    public void digest() throws Exception {
        byte[] result = md.digest(data);
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void getDigestLength() throws Exception {
        Assert.assertEquals(32, md.getDigestLength());
    }

    @Test
    public void updateDigest() throws Exception {
        md.update(data);
        byte[] result = md.digest();
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void updateOffLen() throws Exception {
        byte[] array = new byte[data.length + 10];
        System.arraycopy(data, 0, array, 5, data.length);
        md.update(array, 5, data.length);
        byte[] result = md.digest();
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void digestEmpty() throws Exception {
        byte[] result = md.digest();
        Assert.assertArrayEquals(emptyDigest, result);

        md = ProviderUtil.getMessageDigest(this.alg);
        result = md.digest(new byte[0]);
        Assert.assertArrayEquals(emptyDigest, result);
    }

    @Test
    public void updateEmpty() throws Exception {
        md.update(data, 0, 0);
        byte[] result = md.digest();
        Assert.assertArrayEquals(emptyDigest, result);

        md = ProviderUtil.getMessageDigest(this.alg);
        md.update(new byte[0]);
        result = md.digest();
        Assert.assertArrayEquals(emptyDigest, result);
    }

    @Test
    public void updateByte() throws Exception {
        for (byte b : data) {
            md.update(b);
        }
        byte[] result = md.digest();
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void updateParts() throws Exception {
        md.update(data, 0, 3);
        md.update(data, 3, 3);
        byte[] finalData = Arrays.copyOfRange(data, 6, data.length);
        byte[] result = md.digest(finalData);
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void autoResetAfterDigest() throws Exception {
        md.update(data);
        byte[] result1 = md.digest();
        byte[] result2 = md.digest();
        md.update(data);
        byte[] result3 = md.digest(new byte[0]);

        Assert.assertArrayEquals(dataDigest, result1);
        Assert.assertArrayEquals(emptyDigest, result2);
        Assert.assertArrayEquals(dataDigest, result3);
    }

    @Test
    public void resetAfterUpdate() throws Exception {
        md.update(data, 0, 5);
        md.reset();
        byte[] result = md.digest();
        Assert.assertArrayEquals(emptyDigest, result);
    }
    @Test
    public void resetAfterConstruct() throws Exception {
        md.reset();
        byte[] result = md.digest(data);
        Assert.assertArrayEquals(dataDigest, result);
    }

    @Test
    public void resetAfterDigest() throws Exception {
        md.update(data);
        byte[] result1 = md.digest();
        md.reset();
        byte[] result2 = md.digest();
        Assert.assertArrayEquals(dataDigest, result1);
        Assert.assertArrayEquals(emptyDigest, result2);
    }

    @Test
    public void cloneNoUpdate() throws Exception {
        MessageDigest cl = (MessageDigest) md.clone();

        byte[] result1 = md.digest();
        md.reset();
        MessageDigest cl2 = (MessageDigest) md.clone();
        byte[] result2 = md.digest();
        byte[] result3 = cl.digest();
        byte[] result4 = cl2.digest();

        Assert.assertArrayEquals(emptyDigest, result1);
        Assert.assertArrayEquals(emptyDigest, result2);
        Assert.assertArrayEquals(emptyDigest, result3);
        Assert.assertArrayEquals(emptyDigest, result4);
    }

    @Test
    public void cloneAfterUpdate() throws Exception {
        md.update(data);

        MessageDigest cl = (MessageDigest) md.clone();

        byte[] result1 = md.digest();
        md.reset();
        byte[] result2 = md.digest();
        byte[] result3 = cl.digest();

        Assert.assertArrayEquals(dataDigest, result1);
        Assert.assertArrayEquals(emptyDigest, result2);
        Assert.assertArrayEquals(dataDigest, result3);
    }

}
