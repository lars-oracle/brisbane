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

package com.oracle.test.integration.symciph;

import java.security.AlgorithmParameters;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.InvalidParameterException;
import java.security.Key;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.stream.Stream;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.GCMParameterSpec;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.PBEParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.Arguments;
import org.junit.jupiter.params.provider.MethodSource;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

public class CipherInitTest {

    enum InitVariant {
        INIT_KEY_RANDOM,
        INIT_KEY_PARAMSPEC_RANDOM,
        INIT_KEY_PARAMS_RANDOM,
    }

    Cipher getInstanceProvider(String alg) throws Exception {
        return ProviderUtil.getCipher(alg);
    }

    public CipherInitTest() {}

    static class SecretKeyDummy implements SecretKey {

        private final byte[] key;
        private final String alg;

        public SecretKeyDummy(byte[] key, String alg) {
            this.alg = alg;
            this.key = key;
        }

        @Override
        public String getAlgorithm() {
            return this.alg;
        }

        @Override
        public byte[] getEncoded() {
            return key;
        }

        public byte[] getKey() {
            return key;
        }

        @Override
        public String getFormat() {
            return "RAW";
        }
    }

    static Class getDesEdeEncryptException() {
        return EnvUtil.getPolicy() == EnvUtil.FipsPolicy.NONE ?
                null: InvalidKeyException.class; /* Caused by FIPS violation */
    }

    static AlgorithmParameters getDESedeParameters(byte[] iv) {
        try {
            AlgorithmParameters ap = ProviderUtil.getAlgorithmParameters("DESede");
            ap.init(new IvParameterSpec(iv));
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }
    static AlgorithmParameters getAESParameters(byte[] iv) {
        try {
            AlgorithmParameters ap = ProviderUtil.getAlgorithmParameters("AES");
            ap.init(new IvParameterSpec(iv));
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }
    static AlgorithmParameters getGCMParameters(int taglen, byte[] iv) {
        try {
            AlgorithmParameters ap = ProviderUtil.getAlgorithmParameters("GCM");
            ap.init(new GCMParameterSpec(taglen, iv));
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }
    static AlgorithmParameters getPBEParameters(String alg, byte[] salt, int iterationCount, byte[] iv) {
        try {
            AlgorithmParameters ap = ProviderUtil.getAlgorithmParameters(alg);
            AlgorithmParameterSpec spec;
            if (iv != null) {
                spec = new PBEParameterSpec(salt, iterationCount, new IvParameterSpec(iv));
            } else {
                spec = new PBEParameterSpec(salt, iterationCount);
            }
            ap.init(spec);
            return ap;
        } catch (Exception e) {
            throw new Error("Error setting up AlgorithmParameters", e);
        }
    }

    private static Stream<Arguments> createInitParameters() throws Exception {
        ArrayList<Arguments> initParameters = new ArrayList<>(List.of(
                Arguments.of("AES-cbc:key not SecretKeySpec", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeyDummy(new byte[24], "AES"), new IvParameterSpec(new byte[16]), null)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.add(
                    Arguments.of("DESede-cbc:key not SecretKeySpec", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeyDummy(new byte[24], "DESede"), new IvParameterSpec(new byte[8]), null));
        }
        initParameters.addAll(Arrays.asList(
                Arguments.of("PBES2-AES-cbc:key not SecretKeySpec", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeyDummy(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[16])), null),
                Arguments.of("PBES2-AES-cbc:encrypt no params", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null, null),
                Arguments.of("PBES2-AES-cbc:encrypt null paramSpec", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null, null),
                Arguments.of("PBES2-AES-cbc:encrypt null AlgorithmParameters", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null, null),
                Arguments.of("PBES2-AES-cbc:iter 0", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 0, new IvParameterSpec(new byte[16])), null),
                Arguments.of("PBES2-AES-cbc:NEG:iter 1", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1, new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:iter 999", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 999, new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:iter 10000001", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 10_000_001, new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:iter 1000", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[16])), null),
                Arguments.of("PBES2-AES-cbc:saltlen 16", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[16], 0, new IvParameterSpec(new byte[16])), null),
                Arguments.of("PBES2-AES-cbc:pwdlen 8", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[8], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 0, new IvParameterSpec(new byte[16])), null),

                // Cases: Bad Key lengths - AES: CBC, ECB, CFB, OFB, GCM
                Arguments.of("AES-cbc:NEG:keyLen33", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[33], "AES"),
                        new IvParameterSpec(new byte[16]), InvalidKeyException.class),
                Arguments.of("AES-ecb:NEG:keyLen1", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[1], "AES"),
                        new IvParameterSpec(new byte[16]), InvalidKeyException.class),
                Arguments.of("AES-cfb:NEG:keyLen17", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[17], "AES"),
                        new IvParameterSpec(new byte[16]), InvalidKeyException.class),
                Arguments.of("AES-ofb:NEG:keyLen0", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeyDummy(new byte[0], "AES"),
                        new IvParameterSpec(new byte[16]), InvalidKeyException.class),
                Arguments.of("AES-ctr:NEG:keyLen1", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[1], "AES"),
                        new IvParameterSpec(new byte[16]), InvalidKeyException.class),
                Arguments.of("AES-gcm:NEG:keyLen0", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeyDummy(new byte[0], "AES"),
                        new GCMParameterSpec(128, new byte[12]), InvalidKeyException.class)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.addAll(Arrays.asList(
                    Arguments.of("DESede-cbc:NEG:keyLen33", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(new byte[33], "DESede"),
                            new IvParameterSpec(new byte[8]), InvalidKeyException.class),
                    Arguments.of("DESede-ecb:NEG:keyLen1", "DESede/ECB/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(new byte[1], "DESede"),
                            new IvParameterSpec(new byte[8]), InvalidKeyException.class)));
        }
        initParameters.addAll(Arrays.asList(
                // Cases: Bad Iv lengths = AES: GCM, CBC, OFB, CFB, CTR
                Arguments.of(
                        // FIPS 140-3 requires the GCM nonce (IV) to be generated within the FIPS boundary when
                        // encrypting. See SP 800-38D section 9.1 'Design considerations' & FIPS 140-3
                        // implementation guidance section C.H 'Key/IV Pair Uniqueness Requirements from SP 800-38D'.
                        // However, the SunJSSE provider imports 96-bit and 128-bit IVs for GCM encryption and thus
                        // Jipher permits IVs with at least 96-bits to be imported for GCM encryption.
                        "AES-gcm-encrypt:NEG:ivLen to small", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeyDummy(new byte[32], "AES"), new GCMParameterSpec(128, new byte[11]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of(
                        // OpenSSL only supports GCM nonce up to 1024 bits.
                        "AES-gcm-encrypt:NEG:ivLen to big", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeyDummy(new byte[32], "AES"), new GCMParameterSpec(128, new byte[(1024/8)+1]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-cbc:NEG:ivLen too big", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"),
                        new IvParameterSpec(new byte[17]), InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ofb:NEG:ivLen 0", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"),
                        new IvParameterSpec(new byte[0]), InvalidAlgorithmParameterException.class),
                Arguments.of("AES-cfb:NEG:ivLen too small", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"),
                        new IvParameterSpec(new byte[15]), InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ctr:NEG:ivLen too small", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"),
                        new IvParameterSpec(new byte[8]), InvalidAlgorithmParameterException.class)));

        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.add(
                    Arguments.of("DESede-cbc:NEG:ivLen too big", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"),
                            new IvParameterSpec(new byte[9]), InvalidAlgorithmParameterException.class));
        }
        initParameters.addAll(Arrays.asList(
                // Cases: decrypt without parameters
                Arguments.of("AES-cbc:NEG:decrypt null paramSpec", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-cbc:NEG:decrypt null AlgorithmParameters", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ofb:NEG:decrypt null paramSpec", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ofb:NEG:decrypt null AlgorithmParameters", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-cfb:NEG:decrypt null paramSpec", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-cfb:NEG:decrypt null AlgorithmParameters", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ctr:NEG:decrypt null paramSpec", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ctr:NEG:decrypt null AlgorithmParameters", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:decrypt null paramSpec", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:decrypt null AlgorithmParameters", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null,
                        InvalidAlgorithmParameterException.class)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.addAll(Arrays.asList(
                    Arguments.of("DESede-cbc:NEG:decrypt null paramSpec", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"), null,
                            InvalidAlgorithmParameterException.class),
                    Arguments.of("DESede-cbc:NEG:decrypt null AlgorithmParameters", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"), null,
                            InvalidAlgorithmParameterException.class)));
        }
        initParameters.addAll(Arrays.asList(
                Arguments.of("AES-cbc:NEG:decrypt no params", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidParameterException.class),
                Arguments.of("AES-ofb:NEG:decrypt no params", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null,
                        InvalidParameterException.class),
                Arguments.of("AES-cfb:NEG:decrypt no params", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidParameterException.class),
                Arguments.of("AES-ctr:NEG:decrypt no params", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null,
                        InvalidParameterException.class),
                Arguments.of("AES-gcm:NEG:decrypt no params", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null,
                        InvalidParameterException.class)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.add(
                    Arguments.of("DESede-cbc:NEG:decrypt no params", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"), null,
                            InvalidParameterException.class));
        }
        initParameters.addAll(Arrays.asList(
                Arguments.of("PBES2-AES-cbc:NEG:decrypt null paramSpec", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:decrypt null AlgorithmParameters", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null,
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:decrypt no params", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"), null,
                        InvalidParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:decrypt no IV", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000),
                        InvalidAlgorithmParameterException.class),

                // Cases: ECB - iv parameters specified
                Arguments.of("AES-ecb:NEG:encrypt iv-specified", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ecb:NEG:decrypt iv-specified", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ecb:NEG:encrypt AlgorithmParameter.AES", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getAESParameters(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ecb:NEG:decrypt AlgorithmParameter.AES", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getAESParameters(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-ecb:iv null spec", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ecb:iv null params", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ecb:iv unspecified:", "AES/ECB/PKCS5Padding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),

                // Cases: GCM incorrect parameters
                Arguments.of("AES-gcm:NEG:ivLen 0", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new GCMParameterSpec(128, new byte[0]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:tagLen too large", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new GCMParameterSpec(95, new byte[12]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:tagLen wrong", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new GCMParameterSpec(88, new byte[12]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:tagLen 64", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new GCMParameterSpec(64, new byte[12]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AES-gcm:NEG:not GCMParameterSpec", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), new IvParameterSpec(new byte[12]),
                        InvalidAlgorithmParameterException.class),

                // Cases: PBES2 incorrect parameters
                Arguments.of("PBES2-AES-cbc:NEG:ivLen 0", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[0])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:ivLen too big", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[17])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:ivLen too small", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[15])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:saltLen 0", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[0], 1000, new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:saltlen 15", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[15], 0, new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:pwdlen 7", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[7], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 0, new IvParameterSpec(new byte[16])),
                        InvalidKeyException.class),
                Arguments.of("PBES2-AES-cbc:NEG:not PBEParameterSpec", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("PBES2-AES-cbc:NEG:iter negative", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], -1,new IvParameterSpec(new byte[16])),
                        InvalidAlgorithmParameterException.class),

                // Cases: No IV specified for encrypt - expect generation
                Arguments.of("AES-cbc:iv spec null (autoGen)", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-cfb:iv spec null (autoGen)", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ofb:iv spec null (autoGen)", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ctr:iv spec null (autoGen)", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-gcm:gcm spec null (autoGen)", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-cbc:no iv (autoGen)", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-cfb:no iv (autoGen)", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ofb:no iv (autoGen)", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("AES-ctr:no iv (autoGen)", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, null)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.addAll(Arrays.asList(
                    Arguments.of("DESede-cbc:no iv (autoGen)", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"), null, getDesEdeEncryptException())));
        }
        initParameters.addAll(Arrays.asList(
                Arguments.of("AES-gcm:no iv (autoGen)", "AES/GCM/NoPadding",
                            InitVariant.INIT_KEY_RANDOM, Cipher.ENCRYPT_MODE,
                            new SecretKeySpec(new byte[32], "AES"), null, null),
                Arguments.of("PBES2-AES-cbc:no iv (autoGen)", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        new PBEParameterSpec(new byte[20], 1000), null),

                // Cases: Use AlgorithmParameters
                Arguments.of("AES-cbc:AlgorithmParameter.AES", "AES/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"),getAESParameters(new byte[16]), null),
                Arguments.of("AES-cfb:AlgorithmParameter.AES", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getAESParameters(new byte[16]), null),
                Arguments.of("AES-ofb:AlgorithmParameter.AES", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getAESParameters(new byte[16]), null),
                Arguments.of("AES-ctr:AlgorithmParameter.AES", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getAESParameters(new byte[16]), null),
                Arguments.of("AES-gcm:AlgorithmParameter.GCM", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), getGCMParameters(120, new byte[12]),
                        null),
                Arguments.of("PBES2-AES-cbc:AlgorithmParameter.PBEWithHmacSHA256AndAES_128", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[20], "PBEWithHmacSHA256AndAES_128"),
                        getPBEParameters("PBEWithHmacSHA256AndAES_128", new byte[20], 1234, new byte[16]),
                        null)
                ));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.add(
                    Arguments.of("DESede-cbc:AlgorithmParameter.DESede", "DESede/CBC/PKCS5Padding",
                            InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.DECRYPT_MODE,
                            new SecretKeySpec(new byte[24], "DESede"), getDESedeParameters(new byte[8]), null)
            );
        }
        initParameters.addAll(Arrays.asList(
                // Cases: algorithm with specified key sizes
                Arguments.of("AES-128-gcm:NEG:wrong key length", "AES_128/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-192-gcm:NEG:wrong key length", "AES_192/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-256-gcm:NEG:wrong key length", "AES_256/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-128-cbc:NEG:wrong key length", "AES_128/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-192-cbc:NEG:wrong key length", "AES_192/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-256-cbc:NEG:wrong key length", "AES_256/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-128-ecb:NEG:wrong key length", "AES_128/ECB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-192-ecb:NEG:wrong key length", "AES_192/ECB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-256-ecb:NEG:wrong key length", "AES_256/ECB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-128-cfb:NEG:wrong key length", "AES_128/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-192-cfb:NEG:wrong key length", "AES_192/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-256-cfb:NEG:wrong key length", "AES_256/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-128-ofb:NEG:wrong key length", "AES_128/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-192-ofb:NEG:wrong key length", "AES_192/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[32], "AES"), null, InvalidKeyException.class),
                Arguments.of("AES-256-ofb:NEG:wrong key length", "AES_256/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),

                // Not secret keys.
                Arguments.of("AES-cfb:NEG:Enc:Not SecretKey", "AES/CFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), new IvParameterSpec(new byte[16]),
                        InvalidKeyException.class),
                Arguments.of("AES-ofb:NEG:Dec:Not SecretKey", "AES/OFB/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        KeyUtil.getDummyEcPrivateKey(new byte[0]), new IvParameterSpec(new byte[16]),
                        InvalidKeyException.class),
                Arguments.of("AES-ctr:NEG:Dec:Not SecretKey", "AES/CTR/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        KeyUtil.getDummyEcPrivateKey(new byte[0]), new IvParameterSpec(new byte[16]),
                        InvalidKeyException.class),
                Arguments.of("AES-gcm:NEG:Enc:Not SecretKey", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), null,
                        InvalidKeyException.class),
                Arguments.of("AES-gcm:NEG:Dec:Not SecretKey", "AES/GCM/NoPadding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        KeyUtil.getDummyEcPrivateKey(new byte[0]), new GCMParameterSpec(128, new byte[12]),
                        InvalidKeyException.class)));
        if (FipsProviderInfoUtil.isDESEDESupported()) {
            initParameters.addAll(Arrays.asList(
                Arguments.of("DESede-cbc:NEG:Enc:Not SecretKey", "DESede/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), new IvParameterSpec(new byte[8]),
                        InvalidKeyException.class),
                Arguments.of("DESede-cbc:NEG:Dec:Not SecretKey", "DESede/CBC/PKCS5Padding",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), new IvParameterSpec(new byte[8]),
                        InvalidKeyException.class)));
        }
        initParameters.addAll(Arrays.asList(
                Arguments.of("PBES2-AES-cbc:NEG:Enc:Not SecretKey", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.ENCRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[16])),
                        InvalidKeyException.class),
                Arguments.of("PBES2-AES-cbc:NEG:Dec:Not SecretKey", "PBEWithHmacSHA256AndAES_128",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.DECRYPT_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]),
                        new PBEParameterSpec(new byte[20], 1000, new IvParameterSpec(new byte[16])),
                        InvalidKeyException.class),

                // Wrap ciphers
                Arguments.of("AESWrap:WRAP:null paramsSpec", "AESWrap",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),
                Arguments.of("AESWrap:UNWRAP:null paramsSpec", "AESWrap",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.UNWRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),
                Arguments.of("AESWrap:WRAP:null params", "AESWrap",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),
                Arguments.of("AESWrap:UNWRAP:null params", "AESWrap",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.UNWRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),
                Arguments.of("AESWrapPad:null paramsSpec", "AESWrapPad",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),
                Arguments.of("AESWrapPad:null params", "AESWrapPad",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, null),

                Arguments.of("AESWrap:NEG:not SecretKey", "AESWrap",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad:NEG:not SecretKey", "AESWrapPad",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        KeyUtil.getDummyEcPublicKey(new byte[0]), null, InvalidKeyException.class),
                Arguments.of("AESWrap:NEG:parameterSpec not null", "AESWrap",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AESWrapPad:NEG:parameterSpec not null", "AESWrapPad",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AESWrap:NEG:parameterSpec not null", "AESWrap",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AESWrapPad:NEG:parameterSpec not null", "AESWrapPad",
                        InitVariant.INIT_KEY_PARAMSPEC_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), new IvParameterSpec(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AESWrap:NEG:parameters not null", "AESWrap",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), getAESParameters(new byte[16]),
                        InvalidAlgorithmParameterException.class),
                Arguments.of("AESWrapPad:NEG:parameters not null", "AESWrapPad",
                        InitVariant.INIT_KEY_PARAMS_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), getAESParameters(new byte[16]),
                        InvalidAlgorithmParameterException.class),

                // AESWrapPad
                Arguments.of("AESWrap:NEG:wrong key length(8)", "AESWrap",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[8], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap:NEG:wrong key length(64)", "AESWrap",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[64], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_128:NEG:wrong key length(24)", "AESWrap_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_128:NEG:wrong key length", "AESWrap_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[17], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_192:NEG:wrong key length(16)", "AESWrap_192",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_192:NEG:wrong key length", "AESWrap_192",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[25], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_256:NEG:wrong key length(24)", "AESWrap_256",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrap_256:NEG:wrong key length", "AESWrap_256",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[33], "AES"), null, InvalidKeyException.class),

                // AESWrapPad
                Arguments.of("AESWrapPad:NEG:wrong key length(8)", "AESWrapPad",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[8], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad:NEG:wrong key length(64)", "AESWrapPad",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[64], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_128:NEG:wrong key length(24)", "AESWrapPad_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_128:NEG:wrong key length", "AESWrapPad_128",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[17], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_192:NEG:wrong key length(16)", "AESWrapPad_192",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[16], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_192:NEG:wrong key length", "AESWrapPad_192",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[25], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_256:NEG:wrong key length(24)", "AESWrapPad_256",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE,
                        new SecretKeySpec(new byte[24], "AES"), null, InvalidKeyException.class),
                Arguments.of("AESWrapPad_256:NEG:wrong key length", "AESWrapPad_256",
                        InitVariant.INIT_KEY_RANDOM, Cipher.WRAP_MODE, new SecretKeySpec(new byte[33], "AES"),
                        null, InvalidKeyException.class)
        ));

        return initParameters.stream();
    }

    @ParameterizedTest(name = "{0}({index})")
    @MethodSource("createInitParameters")
    public void initTest(String description, String alg, InitVariant initMethod, int mode, Key key, Object params, Class exception) throws Exception {
        try {
            Cipher c = getInstanceProvider(alg);
            switch (initMethod) {
                case INIT_KEY_RANDOM:
                    c.init(mode, key, (SecureRandom) null);
                    break;
                case INIT_KEY_PARAMSPEC_RANDOM:
                    c.init(mode, key, (AlgorithmParameterSpec) params);
                    break;
                case INIT_KEY_PARAMS_RANDOM:
                    c.init(mode, key, (AlgorithmParameters) params);
                    break;
                default:
                    throw new Error("Invalid parameters in test data.");
            }
            assertNull(exception, "No exception thrown");
            if (mode == Cipher.ENCRYPT_MODE) {
                byte[] ctext = c.doFinal(new byte[16], 0, 16);
                c.init(Cipher.DECRYPT_MODE, key, c.getParameters(), null);
                byte[] decrypted = c.doFinal(ctext, 0, ctext.length);
                Assertions.assertArrayEquals(new byte[16], decrypted, "Encrypt-decrypt failed");
            }

        } catch (Exception e) {
            if (exception == null) {
                throw e;
            } else {
                assertTrue(exception.isInstance(e), "Expected exception " + exception + ", was " + e.getClass());
            }
        }
    }

}
