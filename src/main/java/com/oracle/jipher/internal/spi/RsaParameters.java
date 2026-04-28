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
import java.security.spec.MGF1ParameterSpec;
import java.util.Collections;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

import com.oracle.jipher.internal.asn1.Asn1;
import com.oracle.jipher.internal.asn1.Asn1BerValue;
import com.oracle.jipher.internal.asn1.Asn1DecodeException;
import com.oracle.jipher.internal.asn1.UniversalTag;

import static com.oracle.jipher.internal.asn1.Asn1.explicit;
import static com.oracle.jipher.internal.asn1.Asn1.newOid;
import static com.oracle.jipher.internal.asn1.Asn1.newSequence;
import static com.oracle.jipher.internal.asn1.TagClass.CONTEXT_SPECIFIC;
import static com.oracle.jipher.internal.asn1.TagClass.UNIVERSAL;

/**
 * Base implementation of {@link java.security.AlgorithmParametersSpi} for RSA-based
 * algorithm parameters such as OAEP and PSS.
 *
 * <p>This class provides utility methods for handling ASN.1 encoding/decoding of
 * RSA parameter structures.</p>
 *
 * <p>Sub-classes are expected to implement the {@code engineGetEncoded()} and
 * {@code engineInit(byte[])} methods defined by {@link AlgorithmParametersSpi}.
 * </p>
 */
abstract class RsaParameters extends AlgorithmParametersSpi {

    private static final Asn1BerValue ID_MGF1 = newOid("1.2.840.113549.1.1.8");

    private static final Asn1BerValue ID_SHA1 = newOid("1.3.14.3.2.26");
    private static final Asn1BerValue ID_SHA224 = newOid("2.16.840.1.101.3.4.2.4");
    private static final Asn1BerValue ID_SHA256 = newOid("2.16.840.1.101.3.4.2.1");
    private static final Asn1BerValue ID_SHA384 = newOid("2.16.840.1.101.3.4.2.2");
    private static final Asn1BerValue ID_SHA512 = newOid("2.16.840.1.101.3.4.2.3");

    private static final Map<Asn1BerValue, String> OID_TO_DIGEST_MAP;
    private static final Map<String, Asn1BerValue> DIGEST_TO_OID_MAP;
    static {
        Map<Asn1BerValue, String> oidToDigestMap = new HashMap<>();
        Map<String, Asn1BerValue> digestToOidMap = new HashMap<>();
        updateMaps(oidToDigestMap, digestToOidMap, "SHA-1", ID_SHA1);
        updateMaps(oidToDigestMap, digestToOidMap, "SHA-224", ID_SHA224);
        updateMaps(oidToDigestMap, digestToOidMap, "SHA-256", ID_SHA256);
        updateMaps(oidToDigestMap, digestToOidMap, "SHA-384", ID_SHA384);
        updateMaps(oidToDigestMap, digestToOidMap, "SHA-512", ID_SHA512);
        OID_TO_DIGEST_MAP = Collections.unmodifiableMap(oidToDigestMap);
        DIGEST_TO_OID_MAP = Collections.unmodifiableMap(digestToOidMap);
    }

    private static void updateMaps(Map<Asn1BerValue, String> oidToDigestMap, Map<String, Asn1BerValue> digestToOidMap, String digestName, Asn1BerValue oid) {
        oidToDigestMap.put(oid, digestName);
        digestToOidMap.put(digestName.toLowerCase(), oid);
    }

    /**
     * Returns the parameters encoded in the specified format. If format is null,
     * the primary encoding format for parameters, ASN.1, is used.
     *
     * <p>The {@code format} argument is accepted for compatibility with the
     * {@link java.security.AlgorithmParametersSpi} API but only {@code "ASN.1"}
     * (case-insensitive) is supported. Any other value results in an
     * {@link IllegalArgumentException}.</p>
     *
     * @param format the name of the encoding format (must be {@code "ASN.1"} or {@code null})
     * @return the parameters encoded using the specified encoding scheme
     * @throws IOException if an encoding error occurs
     */
    @Override
    protected byte[] engineGetEncoded(String format) throws IOException {
        if (format != null && !format.equalsIgnoreCase("ASN.1")) {
            throw new IllegalArgumentException("Only supports ASN.1 format");
        }
        return engineGetEncoded();
    }

    /**
     * Imports the parameters from params and decodes them according to the specified
     * decoding format. If format is null, the primary decoding format for parameters,
     * ASN.1, is used.
     *
     * <p>Only the {@code "ASN.1"} format is accepted; other values cause an
     * {@link IllegalArgumentException}.</p>
     *
     * @param params the encoded parameters
     * @param format name of the encoding format (must be {@code "ASN.1"} or {@code null})
     * @throws IOException if a decoding error occurs
     */
    @Override
    protected void engineInit(byte[] params, String format) throws IOException {
        if (format != null && !format.equalsIgnoreCase("ASN.1")) {
            throw new IllegalArgumentException("Only supports ASN.1 format");
        }
        engineInit(params);
    }

    /**
     * Decodes a DER-encoded byte sequence into an array of RSA parameter encodings.
     *
     * @param numParams the expected number of parameters in the sequence
     * @param der the DER-encoded data representing the parameter structure
     * @return an array containing the decoded {@link Asn1BerValue}s
     * @throws Asn1DecodeException if the encoded data does not contain the
     *         expected tags or order
     */
    static Asn1BerValue[] decodeParams(int numParams, byte[] der) {
        Asn1BerValue paramStructure = Asn1.decodeOne(der);
        List<Asn1BerValue> paramList = paramStructure.maxCount(numParams).sequence();
        Asn1BerValue[] pssParams = new Asn1BerValue[numParams];
        int nextTag = 0;
        for (Asn1BerValue pExplicit : paramList) {
            pExplicit.tagClass(CONTEXT_SPECIFIC);
            if (pExplicit.tagValue < nextTag || pExplicit.tagValue >= numParams) {
                throw new Asn1DecodeException(
                        "Unexpected context specific tag value at offset " +
                                pExplicit.offset + "; expected: " + nextTag + ", was: " +
                                pExplicit.tagValue);
            }
            Asn1BerValue param = pExplicit.noTagCheck().explicit().tagClassDeep(UNIVERSAL);
            pssParams[pExplicit.tagValue] = param;
            nextTag = pExplicit.tagValue + 1;
        }
        return pssParams;
    }

    String getHashAlg(Asn1BerValue hashAlgorithm) {
        return hashAlgorithm == null ? "SHA-1" : getDigestAlg(hashAlgorithm, "PSS Digest");
    }

    MGF1ParameterSpec getMgf1Spec(Asn1BerValue maskGenAlgorithm) {
        return maskGenAlgorithm == null ? MGF1ParameterSpec.SHA1 :
                new MGF1ParameterSpec(
                        getDigestAlg(getAlgIdParams(maskGenAlgorithm, ID_MGF1, "MGF"), "MGF1 Digest"));
    }

    static Asn1BerValue getAlgIdParams(Asn1BerValue algId, Asn1BerValue expectedOid, String desc) {
        List<Asn1BerValue> values = getAlgIdContent(algId);
        Asn1BerValue algorithm = values.get(0);
        if (!algorithm.equals(expectedOid)) {
            throw new Asn1DecodeException("Unsupported OAEP " + desc + " algorithm; was: " + algorithm.getOid() +
                    ", expected: " + expectedOid.getOid());
        }
        return values.get(1);
    }

    Asn1BerValue hashAlgToBer(String digestAlg) {
        Asn1BerValue digestOid = DIGEST_TO_OID_MAP.get(digestAlg.toLowerCase());
        if (digestOid != ID_SHA1) {
            return explicit(0).newSequence(digestOid, Asn1.newNull());
        }
        return null;
    }

    Asn1BerValue mgfToBer(MGF1ParameterSpec mgf1Spec) {
        Asn1BerValue mgf1DigestOid = DIGEST_TO_OID_MAP.get(mgf1Spec.getDigestAlgorithm().toLowerCase());
        if (mgf1DigestOid != ID_SHA1) {
            return explicit(1).newSequence(
                    ID_MGF1, newSequence(mgf1DigestOid, Asn1.newNull()));
        }
        return null;
    }

    private static String getDigestAlg(Asn1BerValue algId, String desc) {
        Asn1BerValue digestOid = getDigestOid(algId);
        String digestAlg = OID_TO_DIGEST_MAP.get(digestOid);
        if (digestAlg == null) {
            throw new Asn1DecodeException("Unsupported OAEP " + desc + " algorithm: " + digestOid);
        }
        return digestAlg;
    }

    private static Asn1BerValue getDigestOid(Asn1BerValue algId) {
        List<Asn1BerValue> values = getAlgIdContent(algId);
        values.get(1).getNull();
        return values.get(0);
    }

    private static List<Asn1BerValue> getAlgIdContent(Asn1BerValue algId) {
        List<Asn1BerValue> values = algId.count(2).sequence();
        values.get(0).tag(UniversalTag.OBJECT_IDENTIFIER);
        return values;
    }
}
