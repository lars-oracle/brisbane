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

import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.openssl.Rand;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link javax.crypto.KeyGeneratorSpi} that generates the TLS RSA premaster secret as
 * defined in the TLS specifications.
 *
 * <p>Provides cryptography required by the SunJSSE. Only {@link javax.crypto.KeyGeneratorSpi}
 * {@code engineInit} methods used by the SunJSSE are supported.
 */
public final class TlsRsaPremasterSecretGenerator extends KeyGeneratorSpi {

    private static final int PREMASTER_SECRET_KEY_LEN = 48;
    private static final String MSG = "TlsRsaPremasterSecretGenerator must be initialized using a TlsRsaPremasterSecretParameterSpec";

    private InternalTlsSpec.RsaPremasterSecretParamSpec paramSpec;

    @Override
    protected void engineInit(int keySize, SecureRandom secureRandom) {
        throw new InvalidParameterException(MSG);
    }

    @Override
    protected void engineInit(SecureRandom secureRandom) {
        throw new InvalidParameterException(MSG);
    }

    /**
     * Initializes the generator with the given {@code AlgorithmParameterSpec}.
     *
     * <p>The supplied {@code algorithmParameterSpec} is expected to be a
     * {@code sun.security.internal.spec.RsaPremasterSecretParamSpec}. The
     * {@code SecureRandom} argument is ignored because random data is obtained
     * from the native OpenSSL {@code RAND_bytes} implementation via
     * {@link Rand#generate(int)} when needed.
     *
     * @param algorithmParameterSpec the TLS RSA premaster secret parameter specification
     * @param secureRandom          a source of randomness (ignored)
     * @throws InvalidAlgorithmParameterException if the supplied spec is not of the expected type
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.paramSpec = new InternalTlsSpec.RsaPremasterSecretParamSpec(algorithmParameterSpec);
    }

    /**
     * Generates a {@link javax.crypto.SecretKey} containing the TLS RSA premaster secret.
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (this.paramSpec == null) {
            throw new IllegalStateException("TlsRsaPremasterSecretGenerator must be initialized");
        }

        byte[] premaster = this.paramSpec.getEncodedSecret();
        try {
            if (premaster == null) {
                premaster = Rand.generate(PREMASTER_SECRET_KEY_LEN);
            }
            premaster[0] = (byte) this.paramSpec.getMajorVersion();
            premaster[1] = (byte) this.paramSpec.getMinorVersion();

            return new SecretKeySpec(premaster, "TlsRsaPremasterSecret");
        } finally {
            clearArray(premaster);
        }
    }
}
