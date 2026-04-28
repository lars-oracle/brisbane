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

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TlsUtil;

import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

/**
 * Test the provider implementation of KeyGenerator TlsRsaPremasterSecret
 */
public class TlsRsaPremasterSecretKeyGenTest {

    private KeyGenerator kg;

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTlsRsaPremasterSecret");
    }

    @Test
    public void initGenerate0303() throws Exception {
        AlgorithmParameterSpec rpsParams = TlsUtil.newTlsRsaPremasterSecretParameterSpec(0x0303, 0x0303);
        kg.init(rpsParams);
        SecretKey premasterSecret = kg.generateKey();
        checkRsaPremasterSecret(premasterSecret, 3, 3);
    }

    @Test
    public void initGenerate0301() throws Exception {
        AlgorithmParameterSpec rpsParams = TlsUtil.newTlsRsaPremasterSecretParameterSpec(0x0301, 0x0301);
        kg.init(rpsParams);
        SecretKey premasterSecret = kg.generateKey();
        checkRsaPremasterSecret(premasterSecret, 3, 1);
    }

    @Test
    public void initGenerateWithSecret() throws Exception {
        AlgorithmParameterSpec rpsParams = TlsUtil.newTlsRsaPremasterSecretParameterSpec(0x0301, 0x0301, new byte[48]);
        kg.init(rpsParams);
        SecretKey premasterSecret = kg.generateKey();
        checkRsaPremasterSecret(premasterSecret, 3, 1);
        byte[] encoded = premasterSecret.getEncoded();
        byte[] expected = new byte[48];
        expected[0] = 3;
        expected[1] = 1;
        assertArrayEquals(expected, encoded);
    }

    void checkRsaPremasterSecret(SecretKey premasterSecret, int majorVersion, int minorVersion) throws Exception {
        assertEquals("RAW", premasterSecret.getFormat());
        assertEquals("TlsRsaPremasterSecret", premasterSecret.getAlgorithm());
        byte[] encoded = premasterSecret.getEncoded();
        assertEquals(48, encoded.length);
        assertEquals(majorVersion, encoded[0]);
        assertEquals(minorVersion, encoded[1]);
    }

    @Test
    public void initGenerateTls12AlgName() throws Exception {
        kg = ProviderUtil.getKeyGenerator("SunTls12RsaPremasterSecret");
        initGenerate0301();
    }

    @Test
    public void multipleUse() throws Exception {
        initGenerate0303();
        initGenerate0301();
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
        SecretKey premasterSecret = kg.generateKey();
    }
}
