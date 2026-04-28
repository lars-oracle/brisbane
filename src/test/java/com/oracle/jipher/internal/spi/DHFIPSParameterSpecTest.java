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

package com.oracle.jipher.internal.spi;

import java.math.BigInteger;

import org.junit.Test;

import static org.junit.Assert.assertEquals;

public class DHFIPSParameterSpecTest {

    @Test
    public void constructGet() {
        BigInteger a = BigInteger.valueOf(123);
        BigInteger b = BigInteger.valueOf(223);
        BigInteger c = BigInteger.valueOf(221);
        BigInteger d = BigInteger.valueOf(321);
        DHFIPSParameterValidationSpec e = new DHFIPSParameterValidationSpec("seed".getBytes(), 100);
        int f = 1;

        DHFIPSParameterSpec spec = new DHFIPSParameterSpec(a, b, c, d, e, f);

        assertEquals(a, spec.getP());
        assertEquals(b, spec.getQ());
        assertEquals(c, spec.getG());
        assertEquals(d, spec.getJ());
        assertEquals(e, spec.getParameterValidationSpec());
        assertEquals(f, spec.getL());
    }

    @Test(expected=IllegalArgumentException.class)
    public void nullP() {
        BigInteger a = BigInteger.valueOf(123);
        new DHFIPSParameterSpec(null, a, a);
    }
    @Test(expected=IllegalArgumentException.class)
    public void nullQ() {
        BigInteger a = BigInteger.valueOf(123);
        new DHFIPSParameterSpec(a, null, a);
    }
    @Test(expected=IllegalArgumentException.class)
    public void nullG() {
        BigInteger a = BigInteger.valueOf(123);
        new DHFIPSParameterSpec(a, a, null);
    }

}
