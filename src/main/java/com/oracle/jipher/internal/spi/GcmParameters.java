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
import java.util.List;
import javax.crypto.spec.GCMParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.Util;

import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;

/**
 * Implementation of {@link AlgorithmParametersSpi} for GCM Parameters.
 */
public class GcmParameters extends AlgorithmParametersSpi {

    private GCMParameterSpec gcmSpec;

    @Override
    protected byte[] engineGetEncoded() {
        return Asn1.newSequence(
                Asn1.newOctetString(this.gcmSpec.getIV()),
                Asn1.newInteger(this.gcmSpec.getTLen() / 8)).encodeDerOctets();
    }

    @Override
    protected byte[] engineGetEncoded(String format) {
        return engineGetEncoded();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(GCMParameterSpec.class)) {
            return paramSpec.cast(this.gcmSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from GCMParameterSpec");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            Asn1BerValue gcmParams = Asn1.decodeOne(params).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> gcmPValues = gcmParams.count(2).sequence();
            int tLen = gcmPValues.get(1).getInteger().intValueExact() * 8;
            if (tLen >= 96 && tLen <= 128) { // By construction tLen is a multiple of 8
                this.gcmSpec = new GCMParameterSpec(tLen, gcmPValues.get(0).getOctetString());
            } else {
                throw new IOException("GCM tag length must be {128, 120, 112, 104, 96} bits");
            }
        } catch (Asn1DecodeException|ArithmeticException ex) {
            throw new IOException("Invalid encoding of GCM parameters", ex);
        }
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected String engineToString() {
        return "GCM Parameters [ tagLen = " + gcmSpec.getTLen() + ", iv = " + Util.bytesToHex(gcmSpec.getIV()) + "]";
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof GCMParameterSpec gcmParameterSpec) {
            int tLen = gcmParameterSpec.getTLen();
            if (tLen >= 96 && tLen <= 128 && tLen % 8 == 0) {
                this.gcmSpec = gcmParameterSpec;
            } else {
                throw new InvalidParameterSpecException("GCM tag length must be {128, 120, 112, 104, 96} bits");
            }
        } else {
            throw new InvalidParameterSpecException("Invalid parameter spec, expected GCMParameterSpec");
        }
    }
}
