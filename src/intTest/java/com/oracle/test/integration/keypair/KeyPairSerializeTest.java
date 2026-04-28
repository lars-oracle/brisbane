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

package com.oracle.test.integration.keypair;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.Security;
import java.security.spec.KeySpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.spec.DHPrivateKeySpec;
import javax.crypto.spec.DHPublicKeySpec;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class KeyPairSerializeTest {

    final private String alg;

    @Parameterized.Parameters(name="{0}")
    public static Collection<String> params() throws Exception {
        return Arrays.asList("DH", "EC", "RSA");
    }

    public KeyPairSerializeTest(String algorithm) {
        this.alg = algorithm;
    }

    @Test
    public void serializeDeserializeTest() throws Exception {
        KeyPairGenerator kpg = ProviderUtil.getKeyPairGenerator(this.alg);
        KeyPair keyPair = kpg.generateKeyPair();

        if (this.alg.equals("DH") && Security.getProvider("JipherJCE") == null) {
            // The SunJCE's DH KeyFactory does not support the dhpublicnumber DH parameter encoding in RFC 3279
            // which accommodates Q. It only supports the dhKeyAgreement DH parameter encoding in PKCS #3 section 9
            // which omits Q.  Hence we have to update the DH key to remove Q.
            keyPair = removeQ(keyPair);
        }

        ByteArrayOutputStream baOut = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(baOut);
        objOut.writeObject(keyPair);

        ByteArrayInputStream baIn = new ByteArrayInputStream(baOut.toByteArray());
        ObjectInputStream objIn = new ObjectInputStream(baIn);
        KeyPair deserializedKeyPair = (KeyPair) objIn.readObject();

        checkKeyPair(keyPair, deserializedKeyPair);
    }

    void checkKeyPair(KeyPair expected, KeyPair actual) throws Exception {
        assertEquals(expected.getPrivate(), actual.getPrivate());
        assertEquals(expected.getPublic(),  actual.getPublic());
    }

    // Removes Q from a DH key pair
    KeyPair removeQ(KeyPair keyPair) throws Exception {
        KeyFactory kf = ProviderUtil.getKeyFactory("DH");
        KeySpec pubKeySpec =  kf.getKeySpec(keyPair.getPublic(), DHPublicKeySpec.class);
        KeySpec priKeySpec =  kf.getKeySpec(keyPair.getPrivate(), DHPrivateKeySpec.class);
        return new KeyPair(kf.generatePublic(pubKeySpec), kf.generatePrivate(priKeySpec));
    }
}
