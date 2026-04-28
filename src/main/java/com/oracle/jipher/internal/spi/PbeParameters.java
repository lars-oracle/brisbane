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
import javax.crypto.spec.PBEParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.Util;

import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;

/**
 * {@link AlgorithmParametersSpi} implementation for password-based encryption (PBE).
 * See <a href="https://www.rfc-editor.org/rfc/rfc2898.html#appendix-A.3">RFC 2898 Appendix A.3</a>
 * <p>
 * PBEParameter ::= SEQUENCE {
 *     salt           OCTET STRING,
 *     iterationCount INTEGER
 * }
 */
public final class PbeParameters extends AlgorithmParametersSpi {

    private PBEParameterSpec pbeSpec;

    @Override
    protected byte[] engineGetEncoded() {
        byte[] salt = this.pbeSpec.getSalt();
        int iterationCount = this.pbeSpec.getIterationCount();

        Asn1BerValue pbeParams = newSequence(
            Asn1.newOctetString(salt),
            Asn1.newInteger(iterationCount)
        );
        return pbeParams.encodeDerOctets();
    }

    @Override
    protected byte[] engineGetEncoded(String format) {
        return engineGetEncoded();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(PBEParameterSpec.class)) {
            return paramSpec.cast(this.pbeSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from PBEParameterSpec");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            // Process pkcs-12PbeParams
            Asn1BerValue pbeParamsSeq = Asn1.decodeOne(params).tagClassDeep(UNIVERSAL);
            List<Asn1BerValue> pbeParams = pbeParamsSeq.count(2).sequence();
            byte[] salt = pbeParams.get(0).getOctetString();
            if (salt.length == 0) {
                throw new Asn1DecodeException("Invalid salt parameter");
            }
            int iterationCount = pbeParams.get(1).getInteger().intValueExact();
            if (iterationCount < 1) {
                throw new Asn1DecodeException("Invalid iterationCount parameter");
            }
            this.pbeSpec = new PBEParameterSpec(salt, iterationCount);
        } catch (ArithmeticException | Asn1DecodeException ex) {
            throw new IOException("Invalid PBE parameters", ex);
        }
    }

    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        engineInit(params);
    }

    @Override
    protected String engineToString() {
        StringBuilder sb = new StringBuilder("PBE Parameters");
        if (this.pbeSpec != null) {
            sb.append(" [ salt=")
                    .append(Util.bytesToHex(this.pbeSpec.getSalt()))
                    .append(", iterationCount=")
                    .append(this.pbeSpec.getIterationCount())
                    .append(" ]");
        }
        return sb.toString();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PBEParameterSpec)) {
            throw new InvalidParameterSpecException("Inappropriate parameter specification");
        }
        this.pbeSpec = (PBEParameterSpec) paramSpec;
    }

}
