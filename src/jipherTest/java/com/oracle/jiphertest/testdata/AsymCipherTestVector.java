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
 * Asymmetric cipher test vector.
 */
public class AsymCipherTestVector extends AbstractTestDataItem {

    public static class AsymParams {
        // Fields are not final to allow GSON to mutate them using reflection
        // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
        private String mgfDigestAlg;
        private byte[] psourceVal;
        public AsymParams(String md, byte[] pval) {
            this.mgfDigestAlg = md;
            this.psourceVal = pval;
        }
        public String mgfAlg() {
            return this.mgfDigestAlg;
        }
        public byte[] psourceVal() {
            return this.psourceVal;
        }
    }

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String ptextHex;
    private String ctextHex;
    private String keyId;
    private String pubHex;
    private String privHex;
    private AsymParams asymParams;

    public AsymCipherTestVector(String alg, String ptextHex, String ctextHex, String keyId, AsymParams asymParams) {
        this(alg, ptextHex, ctextHex, keyId);
        this.asymParams = asymParams;
    }

    public AsymCipherTestVector(String alg, String ptextHex, String ctextHex, String keyId) {
        super(alg);
        this.ptextHex = ptextHex;
        this.ctextHex = ctextHex;
        this.keyId = keyId;
    }

    public AsymCipherTestVector(String alg, String ptextHex, String ctextHex, String pubHex, String privHex) {
        super(alg);
        this.ptextHex = ptextHex;
        this.ctextHex = ctextHex;
        this.pubHex = pubHex;
        this.privHex = privHex;
    }

    public AsymParams getParams() {
        return this.asymParams;
    }

    public String getKeyId() {
        return this.keyId;
    }
    public byte[] getData() {
        return TestUtil.hexStringToByteArray(this.ptextHex);
    }
    public byte[] getCiphertext() {
        return TestUtil.hexStringToByteArray(this.ctextHex);
    }

    public String getKeyAlg() {
        if (this.alg.contains("RSA")) {
            return "RSA";
        }
        return null;
    }

    public byte[] getPubBytes() {
        return TestUtil.hexStringToByteArray(this.pubHex);
    }
    public byte[] getPrivBytes() {
        return TestUtil.hexStringToByteArray(this.privHex);
    }


}
