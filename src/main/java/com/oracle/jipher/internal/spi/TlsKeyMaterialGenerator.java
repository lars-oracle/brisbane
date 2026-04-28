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

import java.lang.reflect.Constructor;
import java.lang.reflect.InvocationTargetException;
import java.nio.ByteBuffer;
import java.nio.charset.StandardCharsets;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.ProviderException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.KeyGeneratorSpi;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import com.oracle.jipher.internal.openssl.Kdf;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.common.Util.clearArray;

/**
 * Implementation of {@link javax.crypto.KeyGeneratorSpi} that derives TLS key material
 * from a master secret using the TLS PRF.
 *
 * <p>Provides cryptography required by the SunJSSE. Only {@link javax.crypto.KeyGeneratorSpi}
 * {@code engineInit} methods used by the SunJSSE are supported.
 */
public final class TlsKeyMaterialGenerator extends KeyGeneratorSpi {

    private static final byte[] KEY_EXPANSION_LABEL = "key expansion".getBytes(StandardCharsets.US_ASCII);
    private static final String MSG = "TlsKeyMaterialGenerator must be initialized using a TlsKeyMaterialParameterSpec";
    private static final int TLS1_2_VER = 0x0303;

    private InternalTlsSpec.KeyMaterialParamSpec paramSpec;
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
     * {@code sun.security.internal.spec.TlsKeyMaterialSpec}. The method validates the following:
     * <ul>
     *   <li>The master secret must be in {@code RAW} format.
     *   <li>The protocol version must be TLS 1.2 (0x0303).</li>
     *   <li>A non-zero cipher key length is required (null cipher suites are rejected).</li>
     *   <li>The PRF hash algorithm must be supported by {@link MdAlg}.</li>
     * </ul>
     * If any validation fails, an {@link InvalidAlgorithmParameterException} is thrown.
     */
    @Override
    protected void engineInit(AlgorithmParameterSpec algorithmParameterSpec, SecureRandom secureRandom) throws InvalidAlgorithmParameterException {
        this.paramSpec = null;
        InternalTlsSpec.KeyMaterialParamSpec pSpec = new InternalTlsSpec.KeyMaterialParamSpec(algorithmParameterSpec);
        if (!"RAW".equals(pSpec.getMasterSecret().getFormat())) {
            throw new InvalidAlgorithmParameterException("Key encoding format must be RAW");
        }
        int protocolVersion = (pSpec.getMajorVersion() << 8) | pSpec.getMinorVersion();
        if (protocolVersion != TLS1_2_VER) {
            throw new InvalidAlgorithmParameterException("Only TLS 1.2 supported");
        }
        if (pSpec.getCipherKeyLength() == 0) {
            throw new InvalidAlgorithmParameterException("Null ciphersuites are not supported");
        }
        this.md = MdAlg.byName(pSpec.getPRFHashAlg());
        if (this.md == null) {
            throw new InvalidAlgorithmParameterException("Unsupported PRF hash algorithm");
        }
        this.paramSpec = pSpec;
    }

    /**
     * Generates a {@link SecretKey} containing client and server MAC keys, cipher keys and IVs specified as a
     * {@code sun.security.internal.spec.TlsKeyMaterialSpec}.
     */
    @Override
    protected SecretKey engineGenerateKey() {
        if (this.paramSpec == null) {
            throw new IllegalStateException("TlsKeyMaterialGenerator must be initialized");
        }
        String alg = this.paramSpec.getCipherAlgorithm();
        int macKeyLength = this.paramSpec.getMacKeyLength();
        int keyLength = this.paramSpec.getCipherKeyLength();
        int ivLength = this.paramSpec.getIvLength();
        int keyBlockLen = (macKeyLength + keyLength + ivLength) * 2;

        byte[] masterSecret = this.paramSpec.getMasterSecret().getEncoded();
        byte[] keyBlock = null;
        try {
            keyBlock = Kdf.tls1PrfDerive(masterSecret, KEY_EXPANSION_LABEL,
                    this.paramSpec.getServerRandom(), this.paramSpec.getClientRandom(), this.md, keyBlockLen);
            ByteBuffer keyBlockBuf = ByteBuffer.wrap(keyBlock);

            SecretKey clientMacKey = null;
            SecretKey serverMacKey = null;
            if (macKeyLength != 0) {
                byte[] macKeyBytes = new byte[macKeyLength];
                keyBlockBuf.get(macKeyBytes);
                clientMacKey = new SecretKeySpec(macKeyBytes, "Mac");
                keyBlockBuf.get(macKeyBytes);
                serverMacKey = new SecretKeySpec(macKeyBytes, "Mac");
                clearArray(macKeyBytes);
            }

            byte[] keyBytes = new byte[keyLength];
            keyBlockBuf.get(keyBytes);
            SecretKey clientCipherKey = new SecretKeySpec(keyBytes, alg);
            keyBlockBuf.get(keyBytes);
            SecretKey serverCipherKey = new SecretKeySpec(keyBytes, alg);
            clearArray(keyBytes);

            IvParameterSpec clientIv = null;
            IvParameterSpec serverIv = null;
            if (ivLength != 0) {
                byte[] ivBytes = new byte[ivLength];
                keyBlockBuf.get(ivBytes);
                clientIv = new IvParameterSpec(ivBytes);
                keyBlockBuf.get(ivBytes);
                serverIv = new IvParameterSpec(ivBytes);
                clearArray(ivBytes);
            }

            return newTlsKeyMaterialSpec(clientMacKey, serverMacKey,
                clientCipherKey, clientIv, serverCipherKey, serverIv);
        } finally {
            clearArray(masterSecret);
            clearArray(keyBlock);
        }
    }

    private SecretKey newTlsKeyMaterialSpec(
            SecretKey clientMacKey, SecretKey serverMacKey, SecretKey clientCipherKey, IvParameterSpec clientIv,
            SecretKey serverCipherKey, IvParameterSpec serverIv) {

        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsKeyMaterialSpec");
            Constructor c = specClass.getConstructor(SecretKey.class, SecretKey.class, SecretKey.class, IvParameterSpec.class,
                    SecretKey.class, IvParameterSpec.class);
            return (SecretKey) c.newInstance(clientMacKey, serverMacKey, clientCipherKey, clientIv, serverCipherKey, serverIv);

        } catch (ClassNotFoundException | NoSuchMethodException | InstantiationException | IllegalAccessException | InvocationTargetException e) {
            throw new ProviderException("Unexpected error creating TlsKeyMaterialSpec", e);
        }

    }
}
