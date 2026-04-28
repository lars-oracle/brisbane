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
 * Domain parameters test data.
 */
public class ParameterTestData extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String secParam;
    private String id;
    private String encHex;
    private String genProvider;
    private ParamParts paramParts;

    public ParameterTestData(String alg, String secParam, byte[] enc, ParamParts parts, String genProvider) {
        super(alg);
        this.secParam = secParam;
        this.encHex = (enc != null) ? TestUtil.bytesToHex(enc) : null;
        this.genProvider = genProvider;
        this.id = quickId();
        this.paramParts = parts;
    }

    @Override
    public byte[] getData() {
        return null;
    }

    public String getKeyId() {
        return this.id;
    }

    public String getSecParam() {
        return secParam;
    }

    public String getProvider() {
        return this.genProvider;
    }
    public byte[] getEncoding() throws Exception {
        return TestUtil.hexStringToByteArray(this.encHex);
    }

    private String quickId() {
        // last 10 chars of encoding hex
        return alg + "-" + secParam + "-" + this.encHex.substring(this.encHex.length() - 10);
    }

    public ParamParts getParamParts() {
        return this.paramParts;
    }

    public static class ParamParts {
        private String pHex;
        private String qHex;
        private String gHex;
        private int qLen;

        private int j;
        private String seedHex;
        private int counter;

        public static ParamParts getInstance(byte[] p, byte[] q, byte[] g) {
            ParamParts parts = new ParamParts();
            parts.pHex = TestUtil.bytesToHex(p);
            parts.qHex = (q == null) ? null : TestUtil.bytesToHex(q);
            parts.gHex =TestUtil.bytesToHex(g);
            return parts;
        }

        public static ParamParts getInstance(byte[] p, byte[] q, byte[] g, int j, byte[] seed, int counter) {
            ParamParts parts = getInstance(p, q, g);
            parts.j = j;
            parts.seedHex = TestUtil.bytesToHex(seed);
            parts.counter = counter;
            return parts;
        }
        public byte[] getP() {
            return TestUtil.hexStringToByteArray(pHex);
        }
        public byte[] getQ() {
            return this.qHex == null ? null : TestUtil.hexStringToByteArray(qHex);
        }
        public byte[] getG() {
            return TestUtil.hexStringToByteArray(gHex);
        }
        public byte[] getSeed() {
            return this.seedHex == null ? null : TestUtil.hexStringToByteArray(seedHex);
        }
        public int getJ() {
            return this.j;
        }
        public int getCounter() {
            return counter;
        }
    }

}
