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
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link KeyGeneratorSpi} that derives a TLS PRF (Pseudo-Random Function) key using
 * the OpenSSL KDF implementation.
 *
 * <p>Provides cryptography required by the SunJSSE. Only {@link javax.crypto.KeyGeneratorSpi}
 * {@code engineInit} methods used by the SunJSSE are supported.
 */
public final class TlsPrfGenerator extends KeyGeneratorSpi {

    private static final String MSG = "TlsPrfGenerator must be initialized using a TlsPrfParameterSpec";

    private InternalTlsSpec.PrfParameterSpec paramSpec;
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
     * Initializes the generator with (Pseudo-Random Function) PRF parameters
     *
     * <p>The supplied {@code algorithmParameterSpec} is expected to be a
     * {@code sun.security.internal.spec.TlsPrfParameterSpec} that provides parameters
     * for the TLS PRF defined in <a href=https://www.rfc-editor.org/rfc/rfc2246.html>RFC 2246</a>.
     * The method validates the supplied parameters:
     * <ul>
     *   <li>The secret key (if provided) must have a {@code RAW} encoding.</li>
     *   <li>The PRF hash algorithm must be one of SHA-256, SHA-384 or SHA-512.
     *       Other algorithms are prohibited by FIPS.</li>
     *   <li>Both the label and seed cannot be empty simultaneously.</li>
     * </ul>
     *
     * @param algorithmParameterSpec a spec that can be converted to {@link InternalTlsSpec.PrfParameterSpec}
     * @param secureRandom ignored (required by the SPI signature)
     * @throws InvalidAlgorithmParameterException if any validation fails
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom)
            throws InvalidAlgorithmParameterException {

        InternalTlsSpec.PrfParameterSpec pSpec = new InternalTlsSpec.PrfParameterSpec(algorithmParameterSpec);
        SecretKey key = pSpec.getSecret();
        if (key != null && !"RAW".equals(key.getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
        }
        this.md = MdAlg.byName(pSpec.getPRFHashAlg());
        if (this.md == null) {
            throw new InvalidAlgorithmParameterException("Unsupported PRF hash algorithm");
        }
        if (!(this.md == MdAlg.SHA256 || this.md == MdAlg.SHA384 || this.md == MdAlg.SHA512)) {
            throw new InvalidAlgorithmParameterException(
                    "Unsupported PRF hash algorithm: FIPS disallows TLS PRF hash algorithms other than SHA-256, SHA-384 and SHA-512");
        }
        if (pSpec.getLabel().isEmpty() && pSpec.getSeed().length == 0) {
            throw new InvalidAlgorithmParameterException("Empty label and seed");
        }
        this.paramSpec = pSpec;
    }

    /**
     * Generates the TLS PRF secret key.
     *
     * @return a {@link SecretKeySpec} containing the derived PRF bytes with the
     *         algorithm name {@code "TlsPrf"}
     * @throws IllegalStateException if the generator has not been initialized
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (this.paramSpec == null) {
            throw new IllegalStateException("TlsPrfGenerator must be initialized");
        }
        SecretKey key = this.paramSpec.getSecret();
        byte[] secret = key == null ? null : key.getEncoded();
        byte[] prfBytes = null;
        try {
            prfBytes = Kdf.tls1PrfDerive(secret,
                    this.paramSpec.getLabel().getBytes(StandardCharsets.UTF_8),
                    this.paramSpec.getSeed(), null, this.md, this.paramSpec.getOutputLength());
            return new SecretKeySpec(prfBytes, "TlsPrf");
        } finally {
            clearArray(secret);
            clearArray(prfBytes);
        }
    }
}
