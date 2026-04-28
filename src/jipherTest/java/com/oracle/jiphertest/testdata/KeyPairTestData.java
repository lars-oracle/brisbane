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

import java.security.PrivateKey;
import java.security.PublicKey;

import com.oracle.jiphertest.util.TestUtil;

/**
 * Test data for a key pair.
 */
public class KeyPairTestData extends AbstractTestDataItem {

    // Fields are not final to allow GSON to mutate them using reflection
    // See https://docs.oracle.com/en/java/javase/26/migrate/preparing-final-field-mutation-restrictions.html
    private String secParam;
    private String keyId;
    private String pubHex;
    private String privHex;
    private String genProvider;
    KeyParts keyParts;

    public KeyPairTestData(String alg, String secParam, String pubHex, String privHex, String prov) {
        super(alg);
        this.secParam = secParam;
        this.pubHex = pubHex;
        this.privHex = privHex;
        this.keyId = quickId();
        this.genProvider = prov;
    }

    public PrivateKey getGenericPrivateKey() {
        return new PrivateKey() {
            @Override
            public String getAlgorithm() {
                return alg;
            }
            @Override
            public String getFormat() {
                return "PKCS8";
            }

            @Override
            public byte[] getEncoded() {
                return getPriv().clone();
            }
        };
    }
    public PublicKey getGenericPublicKey() {
        return new PublicKey() {
            @Override
            public String getAlgorithm() {
                return alg;
            }
            @Override
            public String getFormat() {
                return "X.509";
            }

            @Override
            public byte[] getEncoded() {
                return getPub().clone();
            }
        };
    }


    @Override
    public byte[] getData() {
        return null;
    }

    public void setKeyParts(KeyParts keyParts) {
        this.keyParts = keyParts;
    }

    public String getSecParam() {
        return this.secParam;
    }

    public byte[] getPub() {
        return TestUtil.hexStringToByteArray(this.pubHex);
    }

    public byte[] getPriv() {
        return TestUtil.hexStringToByteArray(this.privHex);
    }

    @Override
    public String getKeyId() {
        return keyId;
    }

    private String quickId() {
        // last 10 chars of private key hex
        return alg + "-" + secParam + "-" + this.privHex.substring(this.privHex.length() - 10);
    }

    public KeyParts getKeyParts() {
        return keyParts;
    }

    public String getProvider() {
        return this.genProvider;
    }

    public static class RsaTestKp extends KeyPairTestData {
        private final int bits;

        public RsaTestKp(String alg, int bits, String pubHex, String privHex, String prov) {
            super(alg, "" + bits, pubHex, privHex, prov);
            this.bits = bits;
        }



        public int getBits() {
            return this.bits;
        }

    }

    public static class EcTestKp extends KeyPairTestData {

        public EcTestKp(String alg, String curve, String pubHex, String privHex, String prov) {
            super(alg, curve, pubHex, privHex, prov);
        }

    }

    // For DSA, secParam = "<pLen>-<qlen>"
    public static class DsaTestKp extends KeyPairTestData {

        public DsaTestKp(String alg, String secParam, String pubHex, String privHex, String prov) {
            super(alg, secParam, pubHex, privHex, prov);
        }
    }

    // For DH, secParam = "<pLen>-<qlen>"
    public static class DhTestKp extends KeyPairTestData {

        public DhTestKp(String alg, String secParam, String pubHex, String privHex, String prov) {
            super(alg, secParam, pubHex, privHex, prov);
        }
    }
}
