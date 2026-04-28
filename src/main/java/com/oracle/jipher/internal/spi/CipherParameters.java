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

package com.oracle.jipher.internal.spi;

import java.io.IOException;
import java.security.AlgorithmParametersSpi;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import javax.crypto.spec.IvParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.Util;

/**
 * Parent parameters class for ciphers which need just an IV.
 */
public abstract class CipherParameters extends AlgorithmParametersSpi {

    private IvParameterSpec ivSpec;
    private final CipherAlg alg;

    CipherParameters(CipherAlg alg) {
        this.alg = alg;
    }

    @Override
    protected byte[] engineGetEncoded() {
        return Asn1.newOctetString(this.ivSpec.getIV()).encodeDerOctets();
    }

    @Override
    protected byte[] engineGetEncoded(String format) {
        return engineGetEncoded();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(IvParameterSpec.class)) {
            return paramSpec.cast(this.ivSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from IvParameterSpec");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        byte[] iv;
        try {
            iv = Asn1.decodeOne(params).getOctetString();
        } catch (Asn1DecodeException ex) {
            throw new IOException("Invalid IV encoding", ex);
        }
        if (iv.length != this.alg.getBlockSize()) {
            throw new IOException("Invalid IV encoding (length)");
        }
        this.ivSpec = new IvParameterSpec(iv);
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected String engineToString() {
        return this.alg.getName() + " Parameters [ iv = " + Util.bytesToHex(this.ivSpec.getIV()) + "]";
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof IvParameterSpec)) {
            throw new InvalidParameterSpecException("Invalid parameter spec, expected IvParameterSpec");
        }
        if (((IvParameterSpec) paramSpec).getIV().length != this.alg.getBlockSize()) {
            throw new InvalidParameterSpecException("Invalid IV length");
        }
        this.ivSpec = (IvParameterSpec) paramSpec;
    }

    /**
     * AES AlgorithmParametersSpi class.
     */
    public static final class AesParameters extends CipherParameters {
        public AesParameters() {
            super(new CipherAlg.AES());
        }
    }

    /**
     * DESede AlgorithmParametersSpi class.
     */
    public static final class DESedeParameters extends CipherParameters {
        public DESedeParameters() {
            super(new CipherAlg.DesEde());
        }
    }
}
