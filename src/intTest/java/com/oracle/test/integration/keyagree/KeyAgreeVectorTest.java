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

package com.oracle.test.integration.keyagree;

import java.security.InvalidKeyException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;
import javax.crypto.KeyAgreement;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.KeyAgreeTestVector;
import com.oracle.jiphertest.testdata.KeyPairTestData;
import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.test.integration.KeyUtil;

import static com.oracle.jiphertest.testdata.DataMatchers.keyId;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNull;

@RunWith(Parameterized.class)
public class KeyAgreeVectorTest {
    static List<String> approvedCurves = Arrays.asList(new String[]{"secp224r1", "secp256r1", "secp384r1", "secp521r1"});

    @Parameterized.Parameters(name = "{0}")
    public static Collection<Object[]> data() throws Exception {
        return TestData.forParameterized(KeyAgreeTestVector.class);
    }

    private final String alg;
    private final PrivateKey privKey;
    private final PublicKey peerPubKey;
    private final KeyAgreeTestVector tv;

    public KeyAgreeVectorTest(String description, KeyAgreeTestVector tv) throws Exception {
        this.tv = tv;
        this.alg = tv.getAlg();
        this.privKey = KeyUtil.loadPrivate(tv.getKeyAlg(), TestData.getFirst(KeyPairTestData.class, keyId(tv.getKeyId())).getPriv());
        this.peerPubKey = KeyUtil.loadPublic(tv.getKeyAlg(), tv.getPeerPub());
    }

    @Test
    public void keyAgreement() throws Exception {
        KeyAgreement ka = ProviderUtil.getKeyAgreement(this.alg);

        KeyPairTestData td = TestData.getFirst(KeyPairTestData.class, keyId(this.tv.getKeyId()));
        // ECC Curves and FFC groups that are not approved by SP-800-56A Rev.3 should throw InvalidKeyException
        boolean expectInvalidKeyException = !approvedCurves.contains(td.getSecParam()) &&
                !((this.alg.equals("DH") && Arrays.equals(td.getKeyParts().getG(), new byte[]{2})));

        try {
            ka.init(this.privKey);
            assertNull(ka.doPhase(this.peerPubKey, true));
        } catch (InvalidKeyException e) {
            if (expectInvalidKeyException) return;
            throw (e);
        }
        assertFalse(expectInvalidKeyException);

        byte[] result = ka.generateSecret();
        assertArrayEquals(tv.getSecret(), result);
    }
}
