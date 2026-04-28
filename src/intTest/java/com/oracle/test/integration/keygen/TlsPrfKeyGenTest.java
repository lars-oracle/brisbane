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

package com.oracle.test.integration.keygen;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidParameterException;
import java.security.SecureRandom;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TlsUtil;


import static org.junit.Assert.assertEquals;

public class TlsPrfKeyGenTest {

    private KeyGenerator kg;

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTls12Prf");
    }

    @Test
    public void initGenerate() throws Exception {
        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
            secret, "label", new byte[32], 16, "SHA-256", 32, 64);
        kg.init(prfParams);
        SecretKey key = kg.generateKey();
        assertEquals("RAW", key.getFormat());
        assertEquals("TlsPrf", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length);
    }

    @Test
    public void multipleUse() throws Exception {
        initGenerate();
        initGenerate();
    }

    @Test
    public void initGenerateEmptySeed() throws Exception {
        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
            secret, "label", new byte[0], 16, "SHA-256", 32, 64);
        kg.init(prfParams);
        SecretKey key = kg.generateKey();
        assertEquals("RAW", key.getFormat());
        assertEquals("TlsPrf", key.getAlgorithm());
        assertEquals(16, key.getEncoded().length);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initGenerateEmptyLabelAndSeed() throws Exception {
        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
                secret, "", new byte[0], 16, "SHA-256", 32, 64);
        kg.init(prfParams);
        SecretKey key = kg.generateKey();
    }

    @Test
    public void initGenerateNullKey() throws Exception {
        // The following EXPECTED byte array is the encoding of the derived secret produced by the SunJCE
        // provider for the prfParams used below to generate the key,
        final byte[] EXPECTED = new byte[]{79, -78, -107, 50, 92, -91, 38, 81, -27, 53, -75, 103, -50, 109, 110, 27};

        kg = KeyGenerator.getInstance("SunTls12Prf", "SunJCE");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
            null, "label", new byte[32], 16, "SHA-256", 32, 64);
        kg.init(prfParams);
        SecretKey key = kg.generateKey();
        Assert.assertArrayEquals(key.getEncoded(), EXPECTED);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initUnsupportedPRFHashAlg() throws Exception {
        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
            secret, "label", new byte[32], 16, "SHA-5", 32, 64);
        kg.init(prfParams);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initNullPRFHashAlg() throws Exception {
        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");
        AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
            secret, "label", new byte[32], 16, null, 32, 64);
        kg.init(prfParams);
    }

    static int getHashLen(String hash) {
        String suffix = hash.split("-")[1];
        return suffix.equals("1") ? 20 : Integer.parseInt(suffix) / 8;
    }

    static int getBlockSize(String hash) {
        return switch (hash) {
            case "SHA-1", "SHA-224", "SHA-256" -> 64;
            case "SHA-384", "SHA-512" -> 128;
            case "SHA3-224" -> 144;
            case "SHA3-256" -> 136;
            case "SHA3-384" -> 104;
            case "SHA3-512" -> 72;
            default -> throw new IllegalArgumentException("Invalid hash: " + hash);
        };
    }

    @Test
    public void initDisallowedPRFHashAlg() throws Exception {
        List<String> SUPPORTED_HASH_ALGORITHMS = Arrays.asList("SHA-1",
                "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");
        List<String> ALLOWED_TLS1_PRF_HASH_ALGORITHMS = Arrays.asList("SHA-256", "SHA-384", "SHA-512");

        SecretKey secret = new SecretKeySpec(new byte[48], "Secret");

        for (String prfHashAlg : SUPPORTED_HASH_ALGORITHMS) {
            String suffix = prfHashAlg.split("-")[1];
            int prfHashAlgLength = suffix.equals("1") ? 20 : Integer.parseInt(suffix) / 8;
            AlgorithmParameterSpec prfParams = TlsUtil.newTlsPrfParameterSpec(
                    secret, "label", new byte[32], 16,
                    prfHashAlg, getHashLen(prfHashAlg), getBlockSize(prfHashAlg));
            try {
                kg.init(prfParams);
                Assert.assertTrue(ALLOWED_TLS1_PRF_HASH_ALGORITHMS.contains(prfHashAlg));
            } catch (InvalidAlgorithmParameterException e) {
                Assert.assertFalse(ALLOWED_TLS1_PRF_HASH_ALGORITHMS.contains(prfHashAlg));
            }
        }
    }

    @Test(expected = InvalidParameterException.class)
    public void initKeySize() throws Exception {
        kg.init(1024);
    }

    @Test(expected = InvalidParameterException.class)
    public void initDefault() throws Exception {
        kg.init((SecureRandom)null);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initNullParameters() throws Exception {
        kg.init(null, null);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initInvalidAlgParamSpec() throws Exception {
        kg.init(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test(expected = IllegalStateException.class)
    public void generateWithoutInit() throws Exception {
        SecretKey key = kg.generateKey();
    }
}
