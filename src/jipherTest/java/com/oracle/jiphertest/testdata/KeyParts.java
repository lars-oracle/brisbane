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

import java.security.interfaces.DSAPrivateKey;
import java.security.interfaces.DSAPublicKey;
import java.security.interfaces.ECPrivateKey;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPrivateCrtKey;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.interfaces.DHPublicKey;

import com.oracle.jiphertest.util.TestUtil;

/**
 * Asymmetric key parts.
 */
public class KeyParts {
    private String nHex;
    private String eHex;
    private String dHex;
    private String pHex;
    private String qHex;
    private int l;
    private String expPHex;
    private String expQHex;
    private String crtCoeffHex;

    private String gHex;

    private String privValHex;
    private String pubValHex;
    private String pubXHex;
    private String pubYHex;

    public static KeyParts getInstance(RSAPrivateCrtKey crtKey) {
        KeyParts keyParts = new KeyParts();
        keyParts.nHex = TestUtil.bytesToHex(crtKey.getModulus().toByteArray());
        keyParts.eHex = TestUtil.bytesToHex(crtKey.getPublicExponent().toByteArray());
        keyParts.dHex = TestUtil.bytesToHex(crtKey.getPrivateExponent().toByteArray());
        keyParts.pHex = TestUtil.bytesToHex(crtKey.getPrimeP().toByteArray());
        keyParts.qHex = TestUtil.bytesToHex(crtKey.getPrimeQ().toByteArray());
        keyParts.expPHex = TestUtil.bytesToHex(crtKey.getPrimeExponentP().toByteArray());
        keyParts.expQHex = TestUtil.bytesToHex(crtKey.getPrimeExponentQ().toByteArray());
        keyParts.crtCoeffHex = TestUtil.bytesToHex(crtKey.getCrtCoefficient().toByteArray());
        return keyParts;
    }

    public static KeyParts getInstance(ECPublicKey pub, ECPrivateKey priv) {
        KeyParts keyParts = new KeyParts();
        keyParts.pubXHex = TestUtil.bytesToHex(pub.getW().getAffineX().toByteArray());
        keyParts.pubYHex = TestUtil.bytesToHex(pub.getW().getAffineY().toByteArray());
        keyParts.privValHex = TestUtil.bytesToHex(priv.getS().toByteArray());
        return keyParts;
    }

    public static KeyParts getInstance(DSAPublicKey pub, DSAPrivateKey priv) {
        KeyParts keyParts = new KeyParts();
        keyParts.pubValHex = TestUtil.bytesToHex(pub.getY().toByteArray());
        keyParts.privValHex = TestUtil.bytesToHex(priv.getX().toByteArray());
        keyParts.pHex = TestUtil.bytesToHex(pub.getParams().getP().toByteArray());
        keyParts.qHex = TestUtil.bytesToHex(pub.getParams().getQ().toByteArray());
        keyParts.gHex = TestUtil.bytesToHex(pub.getParams().getG().toByteArray());
        return keyParts;
    }

    public static KeyParts getInstance(DHPublicKey pub, DHPrivateKey priv) {
        KeyParts keyParts = new KeyParts();
        keyParts.pubValHex = TestUtil.bytesToHex(pub.getY().toByteArray());
        keyParts.privValHex = TestUtil.bytesToHex(priv.getX().toByteArray());
        keyParts.pHex = TestUtil.bytesToHex(pub.getParams().getP().toByteArray());
        keyParts.gHex = TestUtil.bytesToHex(pub.getParams().getG().toByteArray());
        keyParts.l = pub.getParams().getL();
        return keyParts;
    }

    public byte[] getN() {
        return TestUtil.hexStringToByteArray(this.nHex);
    }
    public byte[] getE() {
        return TestUtil.hexStringToByteArray(this.eHex);
    }
    public byte[] getD() {
        return TestUtil.hexStringToByteArray(this.dHex);
    }
    public byte[] getP() {
        return TestUtil.hexStringToByteArray(this.pHex);
    }
    public byte[] getQ() {
        if (this.qHex != null) {
            return TestUtil.hexStringToByteArray(this.qHex);
        }
        return null;
    }
    public int getL() {
        return this.l;
    }
    public byte[] getExpP() {
        return TestUtil.hexStringToByteArray(this.expPHex);
    }
    public byte[] getExpQ() {
        return TestUtil.hexStringToByteArray(this.expQHex);
    }
    public byte[] getCrtCoeff() {
        return TestUtil.hexStringToByteArray(this.crtCoeffHex);
    }
    public byte[] getPubX() {
        return TestUtil.hexStringToByteArray(this.pubXHex);
    }
    public byte[] getPubY() {
        return TestUtil.hexStringToByteArray(this.pubYHex);
    }
    public byte[] getPrivValue() {
        return TestUtil.hexStringToByteArray(this.privValHex);
    }
    public byte[] getPubValue() {
        return TestUtil.hexStringToByteArray(this.pubValHex);
    }

    public byte[] getG() {
        return TestUtil.hexStringToByteArray(this.gHex);
    }

}
