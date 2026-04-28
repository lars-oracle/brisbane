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

package com.oracle.test.integration.parameters;

import java.io.IOException;
import java.security.AlgorithmParameters;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;

@RunWith(Parameterized.class)
public class PbeParametersDerNegTest {
    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        return Arrays.asList(
            new Object[] {
                "Empty DER", "PBE", new byte[0]
            },
            new Object[] {
                "Invalid non-universal tag", "PBE",
                hexStringToByteArray("300e810873616c7431323334020207d0")
            },
            new Object[] {
                "Extra field", "PBE",
                hexStringToByteArray("3011040873616c7431323334020207d00101ff")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid salt", "PBE",
                hexStringToByteArray("30060400020207d0")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid zero iteration count", "PBE",
                hexStringToByteArray("300d040873616c7431323334020100")
            },
            new Object[] {
                // Doesn't fail for JDK impl
                "Invalid negative iteration count", "PBE",
                hexStringToByteArray("300d040873616c74313233340201ff")
            }
        );
    }

    private final String alg;
    private final byte[] der;
    private AlgorithmParameters params;

    public PbeParametersDerNegTest(String description, String alg, byte[] der) {
        this.alg = alg;
        this.der = der;
    }

    @Before
    public void setUp() throws Exception {
        params = ProviderUtil.getAlgorithmParameters(this.alg);
    }

    @Test(expected = IOException.class)
    public void initDer() throws Exception {
        params.init(this.der);
    }
}
