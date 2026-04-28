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

import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;

import com.oracle.jipher.internal.fips.CryptoOp;
import com.oracle.jipher.internal.fips.FIPSPolicyException;
import com.oracle.jipher.internal.fips.Fips;
import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;


/**
 * Implementation of {@link javax.crypto.KeyGeneratorSpi} that derives the TLS master secret
 * from a premaster secret using the TLS PRF.
 *
 * <p>Provides cryptography required by the SunJSSE. Only {@link javax.crypto.KeyGeneratorSpi}
 * {@code engineInit} methods used by the SunJSSE are supported.
 */
public final class TlsMasterSecretGenerator extends KeyGeneratorSpi {

    private static final byte[] MASTER_SECRET_LABEL = "master secret".getBytes(StandardCharsets.US_ASCII);
    private static final byte[] EXTENDED_MASTER_SECRET_LABEL = "extended master secret".getBytes(StandardCharsets.US_ASCII);
    private static final int MASTER_SECRET_KEY_LEN = 48;
    private static final String MSG = "TlsMasterSecretGenerator must be initialized using a TlsMasterSecretParameterSpec";
    private static final int TLS1_2_VER = 0x0303;

    private InternalTlsSpec.MasterSecretParameterSpec paramSpec;
    private MdAlg md;

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        throw new InvalidParameterException(MSG);
    }


    /**
     * Initializes this generator with the TLS key material parameters.
     *
     * <p>The supplied {@code algorithmParameterSpec} is expected to be a
     * {@code sun.security.internal.spec.TlsMasterSecretParameterSpec} that provides extended master secret parameters.
     * The method validates the following:
     * <ul>
     *   <li>The encoding must be in {@code RAW} format.
     *   <li>The protocol version must be TLS 1.2 (0x0303).</li>
     *   <li>The PRF hash algorithm must be one allowed by FIPS</li>
     *   <li>The Extended Master Secret Session Hash is provided</li>
     * </ul>
     * If any validation fails, an {@link InvalidAlgorithmParameterException} is thrown.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.paramSpec = null;
        InternalTlsSpec.MasterSecretParameterSpec pSpec = new InternalTlsSpec.MasterSecretParameterSpec(algorithmParameterSpec);
        if (!"RAW".equals(pSpec.getPremasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
        }
        int protocolVersion = (pSpec.getMajorVersion() << 8) | pSpec.getMinorVersion();
        if (protocolVersion != TLS1_2_VER) {
            throw new InvalidAlgorithmParameterException("Only TLS 1.2 supported");
        }
        this.md = MdAlg.byName(pSpec.getPRFHashAlg());
        if (this.md == null) {
            throw new InvalidAlgorithmParameterException("Unsupported PRF hash algorithm");
        }
        if (!(this.md == MdAlg.SHA256 || this.md == MdAlg.SHA384 || this.md == MdAlg.SHA512)) {
            throw new InvalidAlgorithmParameterException("Unsupported PRF hash algorithm: FIPS disallows TLS PRF hash algorithms other than SHA-256, SHA-384 and SHA-512");
        }
        if (pSpec.getExtendedMasterSecretSessionHash() == null ||
                pSpec.getExtendedMasterSecretSessionHash().length == 0) {
            throw new InvalidAlgorithmParameterException("Missing Extended Master Secret Session Hash");
        }

        byte[] premaster = pSpec.getPremasterSecret().getEncoded();
        try {
            Fips.enforcement().checkStrength(CryptoOp.KEYDERIVE, "KDF", premaster.length * 8);
        } catch (FIPSPolicyException e) {
            throw new InvalidAlgorithmParameterException(e.getMessage(), e);
        } finally {
            clearArray(premaster);
        }
        this.paramSpec = pSpec;
    }

    /**
     * Generates a {@link javax.crypto.SecretKey} representing the TLS master secret key
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (this.paramSpec == null) {
            throw new IllegalStateException("TlsMasterSecretGenerator must be initialized");
        }
        SecretKey premasterKey = this.paramSpec.getPremasterSecret();
        byte[] premaster = premasterKey.getEncoded();
        try {
            int premasterMajor, premasterMinor;
            if (premasterKey.getAlgorithm().equals("TlsRsaPremasterSecret")) {
                // RSA
                premasterMajor = premaster[0] & 0xff;
                premasterMinor = premaster[1] & 0xff;
            } else {
                // DH, KRB5, others
                premasterMajor = -1;
                premasterMinor = -1;
            }
            byte[] master = Kdf.tls1PrfDerive(premaster, EXTENDED_MASTER_SECRET_LABEL,
                    this.paramSpec.getExtendedMasterSecretSessionHash(), null, this.md, MASTER_SECRET_KEY_LEN);
            return InternalTlsSpec.newTlsMasterSecretKey(master, premasterMajor, premasterMinor);
        } finally {
            clearArray(premaster);
        }
    }

}
