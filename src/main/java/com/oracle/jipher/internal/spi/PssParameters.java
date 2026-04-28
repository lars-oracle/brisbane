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
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.InvalidParameterSpecException;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;

import static com.oracle.jipher.internal.asn1.Asn1.explicit;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * RSASSA-PSS Parameters.
 *
 * <p> See <a href=https://www.rfc-editor.org/rfc/rfc4055.html#section-6>RFC 4055 Section 6</a>:
 * <pre>
 * RSASSA-PSS-params ::= SEQUENCE {
 *       hashAlgorithm      [0] HashAlgorithm    DEFAULT sha1,
 *       maskGenAlgorithm   [1] MaskGenAlgorithm DEFAULT mgf1SHA1,
 *       saltLength         [2] INTEGER          DEFAULT 20,
 *       trailerField       [3] TrailerField     DEFAULT trailerFieldBC
 *  }
 * </pre>
 */
public final class PssParameters extends RsaParameters {

    private PSSParameterSpec pssSpec;

    @Override
    protected byte[] engineGetEncoded() {
        Asn1BerValue hashAlgorithm = hashAlgToBer(this.pssSpec.getDigestAlgorithm());
        Asn1BerValue maskGenAlgorithm = mgfToBer((MGF1ParameterSpec) this.pssSpec.getMGFParameters());

        Asn1BerValue saltLength = null;
        if (this.pssSpec.getSaltLength() != 20) {
            saltLength = explicit(2).newInteger(this.pssSpec.getSaltLength());
        }
        Asn1BerValue trailerField = null;
        if (this.pssSpec.getTrailerField() != 1) {
            trailerField = explicit(3).newInteger(this.pssSpec.getTrailerField());
        }

        Asn1BerValue rsaPssParams = newSequence(
            hashAlgorithm, maskGenAlgorithm, saltLength, trailerField);
        return rsaPssParams.encodeDerOctets();
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            Asn1BerValue[] pssParams = decodeParams(4, params);
            String hash = getHashAlg(pssParams[0]);
            MGF1ParameterSpec mgfSpec = getMgf1Spec(pssParams[1]);
            Asn1BerValue saltLength = pssParams[2];
            int saltLen = saltLength == null ? 20 : saltLength.getInteger().intValueExact();
            Asn1BerValue trailerField = pssParams[3];
            int tf = trailerField == null ? 1 : trailerField.getInteger().intValueExact();
            this.pssSpec = new PSSParameterSpec(hash, "MGF1", mgfSpec, saltLen, tf);
        } catch (Asn1DecodeException ex) {
            throw new IOException("Invalid PSS parameters", ex);
        }
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(PSSParameterSpec.class)) {
            return paramSpec.cast(this.pssSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from PSSParameterSpec");
    }

    @Override
    protected String engineToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("RSASSA-PSS Parameters [ ");
        sb.append(this.pssSpec.toString());
        sb.append(" ]");
        return sb.toString();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof PSSParameterSpec pSpec)) {
            throw new InvalidParameterSpecException("Invalid parameter spec, expected PSSParameterSpec");
        }
        if (!pSpec.getMGFAlgorithm().equals("MGF1")) {
            throw new InvalidParameterSpecException("Only MGF1 supported.");
        }
        if (!(pSpec.getMGFParameters() instanceof MGF1ParameterSpec)) {
            throw new InvalidParameterSpecException("Unsupported MGF parameters: only MGF1ParameterSpec supported.");
        }
        this.pssSpec = pSpec;
    }
}
