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
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.DigestTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;

/**
 * Test MessageDigest implementations in the provider
 * using test vectors.
 */
@RunWith(Parameterized.class)
public class DigestVectorTest {

    @Parameters(name="{0}:{index}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(DigestTestVector.class);
    }

    private final String alg;
    private final byte[] data;
    private final byte[] digest;

    public DigestVectorTest(String description, DigestTestVector tv) {
        this.alg = tv.getAlg();
        this.data = tv.getData();
        this.digest = tv.getDigest();
    }

    @Test
    public void test() throws Exception {
        MessageDigest md = ProviderUtil.getMessageDigest(this.alg);
        md.update(this.data, 0, this.data.length);
        Assert.assertArrayEquals(this.digest, md.digest());
    }

    @Test
    public void getDigestLength() throws Exception {
        MessageDigest md = ProviderUtil.getMessageDigest(this.alg);
        Assert.assertEquals(this.digest.length, md.getDigestLength());
    }

}
