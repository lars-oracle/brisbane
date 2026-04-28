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

package com.oracle.test.integration.asymciph;

import java.security.AlgorithmParameters;
import java.security.PublicKey;
import java.security.interfaces.RSAPublicKey;
import javax.crypto.Cipher;

import org.junit.Before;
import org.junit.Test;

import com.oracle.jiphertest.testdata.AsymCipherTestVector;
import com.oracle.jiphertest.testdata.DataMatchers;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;

public class AsymCipherMethodTest {
    private static final String ALG = "RSA/ECB/OAEPPadding";
    private static final int IGNORED_INPUT_LENGTH_A = 34;
    private static final int IGNORED_INPUT_LENGTH_B = 3;

    private PublicKey pubKey;
    private AsymCipherTestVector tv;

    @Before
    public void setUp() throws Exception {
        tv = TestData.getFirst(AsymCipherTestVector.class, DataMatchers.alg(ALG));
        KeyPairTestData kp = TestData.getFirst(KeyPairTestData.class, DataMatchers.keyId(tv.getKeyId()));
        pubKey = KeyUtil.loadPublic("RSA", kp.getPub());
    }

    Cipher getInitCipher() throws Exception {
        Cipher c = ProviderUtil.getCipher(ALG);
        c.init(Cipher.ENCRYPT_MODE, pubKey);
        return c;
    }

    @Test(expected = UnsupportedOperationException.class)
    public void updateAad() throws Exception {
        Cipher c = getInitCipher();
        c.updateAAD(tv.getData());
    }

    @Test
    public void getIv() throws Exception {
        Cipher c = getInitCipher();
        assertNull(c.getIV());
    }

    @Test
    public void getParameters() throws Exception {
        Cipher c = getInitCipher();
        AlgorithmParameters algParams = c.getParameters();
        if (c.getAlgorithm().toUpperCase().contains("OAEPPADDING")) {
            assertEquals("OAEP", algParams.getAlgorithm());
        } else {
            assertNull(algParams);
        }
    }

    @Test
    public void getOutputSize() throws Exception {
        int publicKeyByteLength = ((RSAPublicKey) this.pubKey).getModulus().bitLength() / 8;
        Cipher c = getInitCipher();
        assertEquals(publicKeyByteLength, c.getOutputSize(IGNORED_INPUT_LENGTH_A));
        assertEquals(publicKeyByteLength, c.getOutputSize(IGNORED_INPUT_LENGTH_B));
    }

    @Test
    public void getBlockSize() throws Exception {
        Cipher c = getInitCipher();
        assertEquals(0, c.getBlockSize());
    }
}
