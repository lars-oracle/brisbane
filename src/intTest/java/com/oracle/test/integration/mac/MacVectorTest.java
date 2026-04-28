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

package com.oracle.test.integration.mac;

import java.util.Collection;
import javax.crypto.Mac;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

import com.oracle.jiphertest.testdata.MacTestVector;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;

/**
 * Test Mac implementations in the provider
 * using test vectors.
 */
@RunWith(Parameterized.class)
public class MacVectorTest {

    @Parameters(name="{0}:{index}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(MacTestVector.class);
    }

    private final MacTestVector tv;

    public MacVectorTest(String description, MacTestVector tv) {
        this.tv = tv;
    }

    @Test
    public void test() throws Exception {
        Mac md = ProviderUtil.getMac(tv.getAlg());
        md.init(new SecretKeySpec(tv.getKey(), "Mac"));
        md.update(tv.getData(), 0, tv.getData().length);
        Assert.assertArrayEquals(tv.getMac(), md.doFinal());
    }

    @Test
    public void getMacLength() throws Exception {
        Mac md = ProviderUtil.getMac(tv.getAlg());
        Assert.assertEquals(tv.getMac().length, md.getMacLength());
    }

}
