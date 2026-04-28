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
 * Mac test vector.
 */
public class MacTestVector extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String keyHex;
    private String dataHex;
    private String macHex;
    private int dataRepeats;

    public MacTestVector(String alg, String keyHex, String dataHex, String macHex) {
        this(alg, keyHex, dataHex, 1, macHex);
    }
    public MacTestVector(String alg, String keyHex, String dataHex, int repeats, String macHex) {
        super(alg);
        this.keyHex = keyHex;
        this.dataHex = dataHex;
        this.dataRepeats = repeats;
        this.macHex = macHex;
    }

    @Override
    public String getDescription() {
        return this.alg + ":keylen=" + (this.keyHex.length()/2) + ":dataSz=" + getDataSize();
    }

    public byte[] getData() {
        byte[] data = TestUtil.hexStringToByteArray(this.dataHex);
        if (this.dataRepeats == 1) {
            return data;
        }
        byte[] allData = new byte[this.dataRepeats * data.length];
        for (int i = 0; i < dataRepeats; i++) {
            System.arraycopy(data, 0, allData, i*data.length, data.length);
        }
        return allData;
    }

    public byte[] getKey() {
        return TestUtil.hexStringToByteArray(this.keyHex);
    }
    public byte[] getMac() {
        return TestUtil.hexStringToByteArray(this.macHex);
    }

}
