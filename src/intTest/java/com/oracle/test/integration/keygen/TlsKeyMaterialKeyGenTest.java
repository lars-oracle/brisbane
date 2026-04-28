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
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TlsUtil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class TlsKeyMaterialKeyGenTest {

    private KeyGenerator kg;

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTlsKeyMaterial");
    }

    @Test
    public void initGenerateAesGcm() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[32], new byte[32], "AES",
            32, 0, 4, 0, "SHA-256", 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
        SecretKey keyMaterial = kg.generateKey();
        checkKeyMaterial(keyMaterial, 0, 32, 4);
    }

    @Test
    public void initGenerateAesCbc() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[32], new byte[32], "AES",
            16, 0, 16, 32, "SHA-384", 48, 128, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
        SecretKey keyMaterial = kg.generateKey();
        checkKeyMaterial(keyMaterial, 32, 16, 16);
    }

    void checkKeyMaterial(SecretKey km, int macLength, int keyLength, int ivLength) throws Exception {

        Class<?> cls = Class.forName("sun.security.internal.spec.TlsKeyMaterialSpec");

        assertEquals(cls, km.getClass());

        assertNull(km.getFormat());
        assertEquals("TlsKeyMaterial", km.getAlgorithm());
        assertNull(km.getEncoded());

        SecretKey clientMacKey = (SecretKey) cls.getMethod("getClientMacKey").invoke(km);
        SecretKey serverMacKey = (SecretKey) cls.getMethod("getServerMacKey").invoke(km);
        if (macLength != 0) {
            assertEquals("RAW", clientMacKey.getFormat());
            assertEquals("Mac", clientMacKey.getAlgorithm());
            assertEquals("RAW", serverMacKey.getFormat());
            assertEquals("Mac", serverMacKey.getAlgorithm());
            assertEquals(macLength, clientMacKey.getEncoded().length);
            assertEquals(macLength, serverMacKey.getEncoded().length);
        } else {
            assertNull(clientMacKey);
            assertNull(serverMacKey);
        }

        SecretKey clientCipherKey = (SecretKey) cls.getMethod("getClientCipherKey").invoke(km);
        assertEquals("RAW", clientCipherKey.getFormat());
        assertEquals("AES", clientCipherKey.getAlgorithm());
        assertEquals(keyLength, clientCipherKey.getEncoded().length);
        SecretKey serverCipherKey = (SecretKey) cls.getMethod("getServerCipherKey").invoke(km);
        assertEquals("RAW", serverCipherKey.getFormat());
        assertEquals("AES", serverCipherKey.getAlgorithm());
        assertEquals(keyLength, serverCipherKey.getEncoded().length);

        IvParameterSpec clientIv = (IvParameterSpec) cls.getMethod("getClientIv").invoke(km);
        IvParameterSpec serverIv = (IvParameterSpec) cls.getMethod("getServerIv").invoke(km);
        if (ivLength != 0) {
            assertEquals(ivLength, clientIv.getIV().length);
            assertEquals(ivLength, serverIv.getIV().length);
        } else {
            assertNull(clientIv);
            assertNull(serverIv);
        }
    }

    @Test
    public void initGenerateTls12AlgName() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTls12KeyMaterial");
        initGenerateAesGcm();
    }

    @Test
    public void multipleUse() throws Exception {
        initGenerateAesGcm();
        initGenerateAesGcm();
    }

    @Test
    public void initGenerateEmptySalt() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[0], new byte[0],
            "AES", 32, 0, 4, 0, "SHA-256", 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
        SecretKey keyMaterial = kg.generateKey();
        checkKeyMaterial(keyMaterial, 0, 32, 4);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initGenerateNullCipher() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[32], new byte[32],
            "AES", 0, 0, 4, 0, "SHA-256", 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initUnsupportedProtocolVersion() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 2, new byte[32], new byte[32],
            "AES", 32, 0, 4, 0, "NONE", 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initUnsupportedPRFHashAlg() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[32], new byte[32],
            "AES", 32, 0, 4, 0, "SHA-5", 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initNullPRFHashAlg() throws Exception {
        SecretKey masterSecret = new SecretKeySpec(new byte[48], "TlsMasterSecret");
        AlgorithmParameterSpec kmParams = TlsUtil.newTlsKeyMaterialParameterSpec(
            masterSecret, 3, 3, new byte[32], new byte[32],
            "AES", 32, 0, 4, 0, null, 32, 64, "SSL_ECDH_ECDSA_WITH_AES_128_GCM_SHA256");
        kg.init(kmParams);
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
        SecretKey keyMaterial = kg.generateKey();
    }
}
