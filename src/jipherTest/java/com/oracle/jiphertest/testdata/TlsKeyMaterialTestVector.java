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

import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jiphertest.util.TestUtil;

/**
 * TlsKeyMaterialGenerator test vector.
 */
public class TlsKeyMaterialTestVector extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String masterSecretHex;
    private String clientRandomHex;
    private String serverRandomHex;
    private String prfHashAlg;
    private int prfHashLength;
    private int prfBlockSize;
    private String clientMacKeyHex;
    private String serverMacKeyHex;
    private String clientCipherKeyHex;
    private String clientIvHex;
    private String serverCipherKeyHex;
    private String serverIvHex;

    public TlsKeyMaterialTestVector(String alg, String masterSecretHex,
            String clientRandomHex, String serverRandomHex, String prfHashAlg,
            int prfHashLength, int prfBlockSize, String clientMacKeyHex,
            String serverMacKeyHex, String clientCipherKeyHex,
            String clientIvHex, String serverCipherKeyHex, String serverIvHex) {
        super(alg);
        this.masterSecretHex = masterSecretHex;
        this.clientRandomHex = clientRandomHex;
        this.serverRandomHex = serverRandomHex;
        this.prfHashAlg = prfHashAlg;
        this.prfHashLength = prfHashLength;
        this.prfBlockSize = prfBlockSize;
        this.clientMacKeyHex = clientMacKeyHex;
        this.serverMacKeyHex = serverMacKeyHex;
        this.clientCipherKeyHex = clientCipherKeyHex;
        this.clientIvHex = clientIvHex;
        this.serverCipherKeyHex = serverCipherKeyHex;
        this.serverIvHex = serverIvHex;
    }

    @Override
    public String getDescription() {
        return this.alg + ":prfHashAlg=" + this.prfHashAlg
            + ":macKeyLen=" + getMacKeyLength()
            + ":cipherKeyLen=" + getCipherKeyLength()
            + ":ivLen=" + getIvLength();
    }

    @Override
    public byte[] getData() {
        // Not relevant for KdfTestVector
        return null;
    }

    public SecretKey getMasterSecret() {
        return new SecretKeySpec(TestUtil.hexStringToByteArray(this.masterSecretHex), "TlsMasterSecret");
    }

    public byte[] getClientRandom() {
        return TestUtil.hexStringToByteArray(this.clientRandomHex);
    }

    public byte[] getServerRandom() {
        return TestUtil.hexStringToByteArray(this.serverRandomHex);
    }

    public int getCipherKeyLength() {
        return this.clientCipherKeyHex.length() / 2;
    }

    public int getIvLength() {
        return this.clientIvHex != null ? this.clientIvHex.length() / 2 : 0;
    }

    public int getMacKeyLength() {
        return this.clientMacKeyHex != null ? this.clientMacKeyHex.length() / 2 : 0;
    }

    public String getPrfHashAlg() {
        return this.prfHashAlg;
    }

    public int getPrfHashLength() {
        return this.prfHashLength;
    }

    public int getPrfBlockSize() {
        return this.prfBlockSize;
    }

    public byte[] getClientMacKey() {
        return TestUtil.hexStringToByteArray(this.clientMacKeyHex);
    }

    public byte[] getServerMacKey() {
        return TestUtil.hexStringToByteArray(this.serverMacKeyHex);
    }

    public byte[] getClientCipherKey() {
        return TestUtil.hexStringToByteArray(this.clientCipherKeyHex);
    }

    public byte[] getClientIv() {
        return this.clientIvHex == null ? null : TestUtil.hexStringToByteArray(this.clientIvHex);
    }

    public byte[] getServerCipherKey() {
        return TestUtil.hexStringToByteArray(this.serverCipherKeyHex);
    }

    public byte[] getServerIv() {
        return this.serverIvHex == null ? null : TestUtil.hexStringToByteArray(this.serverIvHex);
    }

}
