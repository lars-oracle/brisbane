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
import javax.crypto.spec.OAEPParameterSpec;
import javax.crypto.spec.PSource;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.common.Util;

import static com.oracle.jipher.internal.asn1.Asn1.explicit;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;

/**
 * OAEP Parameter implementation of {@link java.security.AlgorithmParametersSpi}.
 *
 * See <a href=https://www.rfc-editor.org/rfc/rfc8017.html#appendix-A.2.1>RFC 8017 Appendix A.2.1</a>
 * <pre>
 * RSAES-OAEP-params ::= SEQUENCE {
 *   hashAlgorithm      [0] OAEP-PSSDigestAlgorithms     DEFAULT sha1,
 *   maskGenAlgorithm   [1] PKCS1MGFAlgorithms  DEFAULT mgf1SHA1,
 *   pSourceAlgorithm   [2] PKCS1PSourceAlgorithms  DEFAULT pSpecifiedEmpty
 * }
 * </pre>
 */
public class OaepParameters extends RsaParameters {

    private static final Asn1BerValue ID_PSPECIFIED = newOid("1.2.840.113549.1.1.9");

    private OAEPParameterSpec oaepSpec;

    @Override
    protected byte[] engineGetEncoded() {
        Asn1BerValue hashAlgorithm = hashAlgToBer(this.oaepSpec.getDigestAlgorithm());
        Asn1BerValue maskGenAlgorithm = mgfToBer((MGF1ParameterSpec) this.oaepSpec.getMGFParameters());
        Asn1BerValue pSourceAlgorithm = null;
        byte[] pValue = ((PSource.PSpecified)this.oaepSpec.getPSource()).getValue();
        if (pValue.length > 0) {
            pSourceAlgorithm = explicit(2).newSequence(
                ID_PSPECIFIED, Asn1.newOctetString(pValue));
        }

        Asn1BerValue rsaesOaepParams = newSequence(
            hashAlgorithm, maskGenAlgorithm, pSourceAlgorithm);
        return rsaesOaepParams.encodeDerOctets();
    }

    @Override
    protected <T extends AlgorithmParameterSpec> T engineGetParameterSpec(Class<T> paramSpec) throws InvalidParameterSpecException {
        if (paramSpec != null && paramSpec.isAssignableFrom(OAEPParameterSpec.class)) {
            return paramSpec.cast(this.oaepSpec);
        }
        throw new InvalidParameterSpecException("Expected ParameterSpec class to be assignable from OAEPParameterSpec");
    }

    @Override
    protected void engineInit(byte[] params) throws IOException {
        try {
            Asn1BerValue[] oaepParams = decodeParams(3, params);
            String hash = getHashAlg(oaepParams[0]);
            MGF1ParameterSpec mgfSpec = getMgf1Spec(oaepParams[1]);
            Asn1BerValue pSourceAlgorithm = oaepParams[2];
            PSource pSpecified = pSourceAlgorithm == null ?
                PSource.PSpecified.DEFAULT :
                new PSource.PSpecified(getAlgIdParams(pSourceAlgorithm, ID_PSPECIFIED, "PSource").getOctetString());
            this.oaepSpec = new OAEPParameterSpec(hash, "MGF1", mgfSpec, pSpecified);
        } catch (Asn1DecodeException ex) {
            throw new IOException("Invalid OAEP parameters", ex);
        }
    }

    @Override
    protected String engineToString() {
        StringBuilder sb = new StringBuilder();
        sb.append("OAEP Parameters [ ");
        sb.append("MD= ").append(this.oaepSpec.getDigestAlgorithm());
        sb.append(", MGF=MGF1(").append(((MGF1ParameterSpec) this.oaepSpec.getMGFParameters()).getDigestAlgorithm());
        byte[] value = ((PSource.PSpecified) this.oaepSpec.getPSource()).getValue();
        sb.append("), PSource=").append(Util.bytesToHex(value)).append(" ]");
        return sb.toString();
    }

    @Override
    protected void engineInit(AlgorithmParameterSpec paramSpec) throws InvalidParameterSpecException {
        if (!(paramSpec instanceof OAEPParameterSpec oSpec)) {
            throw new InvalidParameterSpecException("Invalid parameter spec, expected OAEPParameterSpec");
        }
        if (!oSpec.getMGFAlgorithm().equals("MGF1")) {
            throw new InvalidParameterSpecException("Only MGF1 supported.");
        }
        if (!(oSpec.getMGFParameters() instanceof MGF1ParameterSpec)) {
            throw new InvalidParameterSpecException("Unsupported MGF parameters: only MGF1ParameterSpec supported.");
        }
        if (!(oSpec.getPSource() instanceof PSource.PSpecified)) {
            throw new InvalidParameterSpecException("Unsupported PSource: only PSource.PSpecified is supported.");
        }
        this.oaepSpec = oSpec;
    }
}
