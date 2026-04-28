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
import javax.crypto.spec.DHParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.Util;

import static com.oracle.jipher.internal.asn1.Asn1.newInteger;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;

/**
 * DH AlgorithmParameterSpi implementation.
 * <p>
 * ASN.1 type from PKCS #3.
 * <pre>
 * DHParameter ::= SEQUENCE {
 *   prime INTEGER, -- p
 *   base INTEGER, -- g
 *   privateValueLength INTEGER OPTIONAL
 * }
 * </pre>
 */
public final class DhParameters extends AlgorithmParametersSpi {

    private DHParameterSpec spec;

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(DHParameterSpec.class)) {
            return paramSpec.cast(this.spec);
        } else {
            throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from DHParameterSpec");
        }
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            Asn1BerValue dhParams = Asn1.decodeOne(params).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> dhPValues = dhParams.count(2, 3).sequence();
            this.spec = new DHParameterSpec(
                    dhPValues.get(0).getInteger(),
                    dhPValues.get(1).getInteger(),
                    dhPValues.size() == 3 ?
                        dhPValues.get(2).getInteger().intValueExact() : 0);
        } catch (ArithmeticException | Asn1DecodeException ex) {
            throw new IOException("Invalid DH parameters", ex);
        }
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (paramSpec instanceof DHParameterSpec) {
            this.spec = (DHParameterSpec) paramSpec;
        } else {
            throw new InvalidParameterSpecException("Invalid parameter spec for DSA parameters");
        }
    }

    @Override
    protected String engineToString() {
        return "DH Parameters (P=" + Util.bytesToHex(this.spec.getP().toByteArray())
                + ",G =" + Util.bytesToHex(this.spec.getG().toByteArray()) + ")";
    }

    @Override
    protected byte[] engineGetEncoded() {
        int l = this.spec.getL();
        Asn1BerValue dhParams = newSequence(
            newInteger(this.spec.getP()),
            newInteger(this.spec.getG()),
            l > 0 ? newInteger(l) : null
        );
        return dhParams.encodeDerOctets();
    }

    @Override
    protected byte[] engineGetEncoded(String format) {
        return engineGetEncoded();
    }
}
