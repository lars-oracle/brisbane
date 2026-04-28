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

package com.oracle.jipher.internal.openssl;

import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collection;

import org.junit.After;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyAgreeTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;

import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static org.junit.Assert.assertArrayEquals;

/**
 * Test EVP_PKEY_derive_init_ex, EVP_PKEY_derive_set_peer_ex & EVP_PKEY_derive using test vectors.
 */
@RunWith(Parameterized.class)
public class EvpPkeyDeriveVectorTest extends EvpTest {

    @Parameterized.Parameters(name = "{index}: {0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(KeyAgreeTestVector.class);
    }

    private final KeySpec privateKeySpec;
    private final KeySpec peerPublicKeySpec;
    private final byte[] secret;

    private EVP_PKEY_CTX deriveCtx;
    private EVP_PKEY peerPublicKey;

    public EvpPkeyDeriveVectorTest(String description, KeyAgreeTestVector tv) throws Exception {
        KeyPairTestData keyPairTestData = TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId()));
        this.privateKeySpec = KeyUtil.getPrivateKeySpec(keyPairTestData.getAlg(), keyPairTestData.getSecParam(), keyPairTestData.getKeyParts());
        this.peerPublicKeySpec = KeyUtil.getPublicKeySpec(tv.getKeyAlg(), tv.getPeerPub());
        this.secret = tv.getSecret();
    }

    @Override
    public void setUp() throws Exception {
        super.setUp();
        EVP_PKEY privateKey = KeyUtil.loadPrivate(this.privateKeySpec, this.libCtx, this.testArena);
        deriveCtx = libCtx.newPkeyCtx(privateKey, null, this.testArena);

        // Configure OpenSSL's DH (FFC) key establishment to retain leading zero bytes of the shared secret
        OSSL_PARAM param = OSSL_PARAM.of(EVP_PKEY.EXCHANGE_PARAM_PAD, 1);
        deriveCtx.deriveInit(param);

        this.peerPublicKey = KeyUtil.loadPublic(this.peerPublicKeySpec, this.libCtx, this.testArena);
    }

    @After
    public void tearDown() throws Exception {
        super.tearDown();
    }

    @Test
    public void deriveSetPeer() throws Exception {
        // This test and its no peer validation counterpart increase code coverage.
        deriveCtx.deriveSetPeer(this.peerPublicKey);
    }

    @Test
    public void deriveSetPeerWithoutValidation() throws Exception {
        // This test and its peer validation counterpart increase code coverage.
        deriveCtx.deriveSetPeer(this.peerPublicKey, false);
    }

    @Test
    public void derive() throws Exception {
        deriveCtx.deriveSetPeer(this.peerPublicKey);

        int outLen = deriveCtx.derive(null, 0);
        byte[] output = new byte[outLen];
        outLen = deriveCtx.derive(output, 0);
        if (outLen != output.length) {
            output = Arrays.copyOfRange(output, 0, outLen);
        }

        assertArrayEquals(this.secret, output);
    }
}
