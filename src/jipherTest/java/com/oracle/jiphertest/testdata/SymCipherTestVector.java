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

import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;

import com.oracle.jiphertest.util.TestUtil;

/**
 * Symmetric Cipher test vector.
 */
public class SymCipherTestVector extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String ptextHex;
    private String ctextHex;
    private String keyHex;
    private String authTagHex;
    private String aadHex;
    private CipherParams ciphParams;

    public SymCipherTestVector(String alg, String ptextHex, String ctextHex, String keyHex, CipherParams ciphParams) {
        super(alg);
        this.ptextHex = ptextHex;
        this.ctextHex = ctextHex;
        this.keyHex = keyHex;
        this.ciphParams = ciphParams;
    }
    public SymCipherTestVector(String alg, String ptextHex, String ctextHex, String keyHex, CipherParams ciphParams, String aadHex, String authTagHex) {
        this(alg, ptextHex, ctextHex, keyHex, ciphParams);
        this.aadHex = aadHex;
        this.authTagHex = authTagHex;
    }

    public byte[] getKey() {
        return TestUtil.hexStringToByteArray(this.keyHex);
    }
    public byte[] getData() {
        return TestUtil.hexStringToByteArray(this.ptextHex);
    }
    public byte[] getCiphertext() {
        return TestUtil.hexStringToByteArray(this.ctextHex);
    }
    public byte[] getAad() {
        if (aadHex == null) {
            return null;
        }
        return TestUtil.hexStringToByteArray(this.aadHex);
    }
    public byte[] getAuthTag() {
        return TestUtil.hexStringToByteArray(this.authTagHex);
    }

    public CipherParams getCiphParams() {
        return this.ciphParams;
    }

    public int getAadLen() {
        if (aadHex == null) {
            return 0;
        }
        return aadHex.length()/2;
    }

    public static IvParameterSpec genIv(int len) {
        byte[] iv = TestUtil.randomBytes(len);
        return new IvParameterSpec(iv, 0, iv.length);
    }

    public static GCMParameterSpec genGcmParams(int tLenBits, int ivLen) {
        byte[] iv = TestUtil.randomBytes(ivLen);
        return new GCMParameterSpec(tLenBits, iv, 0, iv.length);
    }

    public static class CipherParams {
        // Fields are not final to allow GSON to mutate them using reflection
        // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
        private String ivHex;
        private String tagLen;
        public CipherParams(byte[] iv) {
            this.ivHex = TestUtil.bytesToHex(iv);
            this.tagLen = "0";
        }
        public CipherParams(byte[] iv, String tagLen) {
            this.ivHex = TestUtil.bytesToHex(iv);
            this.tagLen = tagLen;
        }
        public byte[] getIv() {
            return TestUtil.hexStringToByteArray(this.ivHex);
        }
        public int getTagLen() {
            return Integer.parseInt(this.tagLen);
        }
    }
}
