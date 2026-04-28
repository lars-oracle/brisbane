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

import java.nio.charset.StandardCharsets;

import com.oracle.jiphertest.util.TestUtil;

/**
 * PBKDF test vector.
 */
public class PbkdfTestVector extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String passwordHex;
    private String saltHex;
    private int iterationCount;
    private String dkHex;

    public PbkdfTestVector(String alg, String passwordHex, String saltHex, int iterationCount, String dkHex) {
        super(alg);
        this.passwordHex = passwordHex;
        this.saltHex = saltHex;
        this.iterationCount = iterationCount;
        this.dkHex = dkHex;
    }

    @Override
    public String getDescription() {
        return this.alg + ":pwLen=" + (this.passwordHex.length()/2) + ":saltLen=" + (this.saltHex.length()/2) + ":dkLen=" + (this.dkHex.length()/2);
    }

    @Override
    public byte[] getData() {
        // Not relevant for KdfTestVector
        return null;
    }

    public byte[] getPasswordBytes() {
        return TestUtil.hexStringToByteArray(this.passwordHex);
    }

    public char[] getPasswordChars() {
        byte[] password = getPasswordBytes();
        return new String(password, StandardCharsets.UTF_8).toCharArray();
    }

    public byte[] getSalt() {
        return TestUtil.hexStringToByteArray(this.saltHex);
    }

    public int getIterationCount() {
        return this.iterationCount;
    }

    public byte[] getDk() {
        return TestUtil.hexStringToByteArray(this.dkHex);
    }

}
