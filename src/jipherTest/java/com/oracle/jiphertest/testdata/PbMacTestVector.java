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

package com.oracle.jiphertest.testdata;

import com.oracle.jiphertest.util.TestUtil;

/**
 * PB Mac test vector.
 */
public class PbMacTestVector extends MacTestVector {

    // Field is not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private PbParams pbParams;

    public PbMacTestVector(String alg, String dataHex, String macHex, PbParams pbParams) {
        this(alg, dataHex, 1, macHex, pbParams);
    }

    public PbMacTestVector(String alg, String dataHex, int repeats, String macHex, PbParams pbParams) {
        super(alg, null, dataHex, repeats, macHex);
        this.pbParams = pbParams;
    }

    @Override
    public String getDescription() {
        return this.alg + ":dataSz=" + getDataSize();
    }

    public PbParams getPbParams() {
        return this.pbParams;
    }

    public static class PbParams {
        // Fields are not final to allow GSON to mutate them using reflection
        // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
        private String password;
        private String saltHex;
        private int iterationCount;
        public PbParams(String password, byte[] salt, int iterationCount) {
            this.password = password;
            this.saltHex = TestUtil.bytesToHex(salt);
            this.iterationCount = iterationCount;
        }
        public char[] getPassword() {
            return this.password.toCharArray();
        }
        public byte[] getSalt() {
            return TestUtil.hexStringToByteArray(this.saltHex);
        }
        public int getIterationCount() {
            return this.iterationCount;
        }
    }
}
