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

public class TlsMasterSecretKeyGenTest {

    static final ProtocolVersion TLS_1_1 = new ProtocolVersion(3, 2);
    static final ProtocolVersion TLS_1_2 = new ProtocolVersion(3, 3);
    static final byte[] EMS_SESSION_HASH = new byte[48];

    private KeyGenerator kg;

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTlsExtendedMasterSecret");
    }

    private void init() throws InvalidAlgorithmParameterException {
        init("SHA-256");
    }

    private void init(String prfHash) throws InvalidAlgorithmParameterException {
        init(TLS_1_2, EMS_SESSION_HASH, prfHash);
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
            default -> throw new InvalidParameterException("Invalid hash: " + hash);
        };
    }

    private void init(ProtocolVersion protocolVersion, byte[] extendedMasterSecretSessionHash, String prfHash) throws InvalidAlgorithmParameterException {
        int prfHashLength;
        int prfBlockSize;

        try {
            prfHashLength = getHashLen(prfHash);
            prfBlockSize = getBlockSize(prfHash);
        } catch (NullPointerException | InvalidParameterException e) {
            // For null or invalid hash algorithm names (used by negative tests) default to 0
            prfHashLength = 0;
            prfBlockSize = 0;
        }

        SecretKey premasterSecret = new SecretKeySpec(new byte[48], "TlsPremasterSecret");
        AlgorithmParameterSpec msParams = TlsUtil.newTlsMasterSecretParameterSpec(
                premasterSecret, protocolVersion.major, protocolVersion.minor,
                extendedMasterSecretSessionHash, prfHash, prfHashLength, prfBlockSize);
        kg.init(msParams);
    }

    private void checkKey(SecretKey masterSecret, int secretKeyLen, int maj, int min) throws Exception {
        assertEquals("RAW", masterSecret.getFormat());
        assertEquals("TlsMasterSecret", masterSecret.getAlgorithm());
        assertEquals(secretKeyLen, masterSecret.getEncoded().length);
        assertEquals(maj, TlsUtil.getTlsMasterSecretClass().getMethod("getMajorVersion").invoke(masterSecret));
        assertEquals(min, TlsUtil.getTlsMasterSecretClass().getMethod("getMinorVersion").invoke(masterSecret));
    }

    @Test
    public void initGenerateExtended() throws Exception {
        init();
        SecretKey masterSecret = kg.generateKey();
        checkKey(masterSecret, 48, -1, -1);
    }

    @Test
    public void initGenerateExtendedMultipleUse() throws Exception {
        for (int i = 0; i < 2; i++) {
            init();
            SecretKey masterSecret = kg.generateKey();
            checkKey(masterSecret, 48, -1, -1);
        }
    }

    @Test
    public void initGenerateExtendedFromRsaPremaster() throws Exception {
        byte[] premaster = new byte[48];
        premaster[0] = 3;
        premaster[1] = 1;
        SecretKey premasterSecret = new SecretKeySpec(premaster, "TlsRsaPremasterSecret");
        AlgorithmParameterSpec msParams = TlsUtil.newTlsMasterSecretParameterSpec(
            premasterSecret, TLS_1_2.major, TLS_1_2.minor, EMS_SESSION_HASH,
            "SHA-256", 32, 64);
        kg.init(msParams);
        SecretKey masterSecret = kg.generateKey();
        checkKey(masterSecret, 48, 3, 1);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initUnsupportedProtocolVersion() throws Exception {
        init(TLS_1_1, EMS_SESSION_HASH, "SHA-256");
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initUnsupportedPRFHashAlg() throws Exception {
        init("SHA-5");
    }

    @Test
    public void initDisallowedPRFHashAlg() throws Exception {
        List<String> SUPPORTED_HASH_ALGORITHMS = Arrays.asList("SHA-1",
                "SHA-224", "SHA-256", "SHA-384", "SHA-512",
                "SHA3-224", "SHA3-256", "SHA3-384", "SHA3-512");
        List<String> ALLOWED_TLS1_PRF_HASH_ALGORITHMS = Arrays.asList("SHA-256", "SHA-384", "SHA-512");

        for (String prfHashAlg : SUPPORTED_HASH_ALGORITHMS) {
            try {
                init(prfHashAlg);
                Assert.assertTrue(ALLOWED_TLS1_PRF_HASH_ALGORITHMS.contains(prfHashAlg));
            } catch (InvalidAlgorithmParameterException e) {
                Assert.assertFalse(ALLOWED_TLS1_PRF_HASH_ALGORITHMS.contains(prfHashAlg));
            }
        }
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initNullPRFHashAlg() throws Exception {
        init(null);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initNullExtendedMasterSecretSessionHash() throws Exception {
        SecretKey premasterSecret = new SecretKeySpec(new byte[48], "TlsPremasterSecret");
        AlgorithmParameterSpec msParams = TlsUtil.newTlsMasterSecretParameterSpec(
                premasterSecret, TLS_1_2.major, TLS_1_2.minor, null,
                "SHA-256", 256, 64);
        kg.init(msParams);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initEmptyExtendedMasterSecretSessionHash() throws Exception {
        SecretKey premasterSecret = new SecretKeySpec(new byte[48], "TlsPremasterSecret");
        AlgorithmParameterSpec msParams = TlsUtil.newTlsMasterSecretParameterSpec(
                premasterSecret, TLS_1_2.major, TLS_1_2.minor, new byte[0],
                "SHA-256", 256, 64);
        kg.init(msParams);
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
        kg.generateKey();
    }

    static class ProtocolVersion {
        int major;
        int minor;
        ProtocolVersion(int major, int minor) {
            this.major = major;
            this.minor = minor;
        }
    }
}
