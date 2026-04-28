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

package com.oracle.test.integration.secretkey;

import java.io.ByteArrayInputStream;
import java.io.ByteArrayOutputStream;
import java.io.ObjectInputStream;
import java.io.ObjectOutputStream;
import javax.crypto.SecretKey;
import javax.crypto.SecretKeyFactory;
import javax.crypto.interfaces.PBEKey;
import javax.crypto.spec.PBEKeySpec;

import org.junit.Assert;
import org.junit.Test;

import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.TestUtil.hexStringToByteArray;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;

public class SecretKeySerializeTest {

    static final char[] PASSWORD = "password".toCharArray();
    static final byte[] SALT = hexStringToByteArray("00112233445566778899AABBCCDDEEFF");
    static final int ITERATION_COUNT = 1000;
    static final int KEY_LENGTH = 256;
    static final PBEKeySpec PBE_SPEC = new PBEKeySpec(PASSWORD, SALT, ITERATION_COUNT, KEY_LENGTH);

    @Test
    public void serializeDeserializePbeKeyTest() throws Exception {
        SecretKeyFactory skf = ProviderUtil.getSecretKeyFactory("PBEWithHmacSHA256AndAES_256");
        SecretKey secretKey = skf.generateSecret(PBE_SPEC);

        ByteArrayOutputStream baOut = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(baOut);
        objOut.writeObject(secretKey);

        ByteArrayInputStream baIn = new ByteArrayInputStream(baOut.toByteArray());
        ObjectInputStream objIn = new ObjectInputStream(baIn);
        SecretKey deserializedSecretKey = (SecretKey) objIn.readObject();

        checkSecretKey(secretKey, deserializedSecretKey);
    }

    @Test
    public void serializeDeserializePbkdf2KeyTest() throws Exception {
        SecretKeyFactory skf = ProviderUtil.getSecretKeyFactory("PBKDF2WithHmacSHA256");
        SecretKey secretKey = skf.generateSecret(PBE_SPEC);

        ByteArrayOutputStream baOut = new ByteArrayOutputStream();
        ObjectOutputStream objOut = new ObjectOutputStream(baOut);
        objOut.writeObject(secretKey);

        ByteArrayInputStream baIn = new ByteArrayInputStream(baOut.toByteArray());
        ObjectInputStream objIn = new ObjectInputStream(baIn);
        SecretKey deserializedSecretKey = (SecretKey) objIn.readObject();

        checkSecretKey(secretKey, deserializedSecretKey);

        Assert.assertTrue(deserializedSecretKey instanceof PBEKey);
        checkPbeKey((PBEKey) secretKey, (PBEKey)  deserializedSecretKey);
    }

    void checkSecretKey(SecretKey expected, SecretKey actual) throws Exception {
        assertEquals(expected.getAlgorithm(), actual.getAlgorithm());
        assertEquals(expected.getFormat(), actual.getFormat());
        assertArrayEquals(expected.getEncoded(), actual.getEncoded());
        assertEquals(expected.isDestroyed(),  actual.isDestroyed());
    }

    void checkPbeKey(PBEKey expected, PBEKey actual) throws Exception {
        checkSecretKey(expected, actual);
        assertArrayEquals(expected.getPassword(), actual.getPassword());
        assertArrayEquals(expected.getSalt(), actual.getSalt());
        assertEquals(expected.getIterationCount(), actual.getIterationCount());
    }
}
