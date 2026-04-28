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
 * Signature test vector.
 */
public class SignatureTestVector extends AbstractTestDataItem {

    public static class SigParams {
        // Fields are not final to allow GSON to mutate them using reflection
        // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
        private int saltLen;
        private String digest;
        public SigParams(int saltLen, String digest) {
            this.saltLen = saltLen;
            this.digest = digest;
        }
        public int getSaltLen() {
            return this.saltLen;
        }
        public String digest() {
            return this.digest;
        }
    }

    private String dataHex;
    private int dataRepeat = 1;
    private String signatureHex;
    private String keyId;
    private SigParams params = null;
    private String pubHex;
    private String privHex;

    public SignatureTestVector(String alg, String dataHex, int dataRepeat, String signatureHex, SigParams params, String keyId) {
        this(alg, dataHex, dataRepeat, signatureHex, keyId);
        this.params = params;
    }

    public SignatureTestVector(String alg, String dataHex, int dataRepeat, String signatureHex, String keyId) {
        this(alg, dataHex, signatureHex, keyId);
        this.dataRepeat = dataRepeat;
    }

    public SignatureTestVector(String alg, String dataHex, String signatureHex, String keyId) {
        super(alg);
        this.dataHex = dataHex;
        this.signatureHex = signatureHex;
        this.keyId = keyId;
    }

    public SigParams getParams() {
        return this.params;
    }

    public String getDescription() {
        if (this.params == null) {
            return this.alg + ":" + this.keyId + ":data=" + getDataSize();
        }
        return this.alg + ":" + (this.params.digest == null ? "" : this.params.digest) + ":" + this.keyId + ":saltlen=" + this.params.saltLen + ":data=" + getDataSize();
    }

    @Override
    public String getKeyId() {
        return this.keyId;
    }

    public byte[] getData() {
        byte[] data = TestUtil.hexStringToByteArray(this.dataHex);
        if (this.dataRepeat == 1) {
            return data;
        }
        byte[] allData = new byte[this.dataRepeat * data.length];
        for (int i = 0; i < dataRepeat; i++) {
            System.arraycopy(data, 0, allData, i*data.length, data.length);
        }
        return allData;
    }

    public byte[] getSignature() {
        return TestUtil.hexStringToByteArray(this.signatureHex);
    }


}
