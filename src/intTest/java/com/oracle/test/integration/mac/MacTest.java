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

package com.oracle.test.integration.mac;

import java.nio.ByteBuffer;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.security.spec.ECGenParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TestUtil;
import com.oracle.test.integration.KeyUtil;

@RunWith(Parameterized.class)
public class MacTest {

    @Parameterized.Parameters(name="{0} ({index})")
    public static Collection<Object[]> cases() throws Exception {
        ArrayList<Object[]> cases = new ArrayList<>();
        cases.add(
                new Object[]{
                    /*
                     * Test case [3] from RFC 4231 section 4.4
                     * https://www.rfc-editor.org/rfc/rfc4231.html#section-4.4
                     */
                    "HmacSHA256",
                    TestUtil.hexStringToByteArray("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"),
                    null,
                    TestUtil.hexStringToByteArray(
                        "dddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddddd"),
                    TestUtil.hexStringToByteArray("773ea91e36800e46854db8ebd09181a72959098b3ef8c122d9635514ced565fe"),
                    // Empty mac. This mac computed from SunJCE provider impl.
                    TestUtil.hexStringToByteArray("86E54FD448725D7E5DCFE22353C828AF48781EB48CAE8106A7E1D498949F3E46")
                });

        return cases;
    }

    String alg;
    byte[] data;
    byte[] dataMac;
    byte[] emptyMac;

    SecretKey macKey;
    AlgorithmParameterSpec algParamSpec;
    Mac mac;

    public MacTest(String alg, byte[] key, AlgorithmParameterSpec algParamSpec, byte[] data, byte[] dataMac, byte[] emptyMac) throws Exception {
        this.alg = alg;
        this.algParamSpec = algParamSpec;
        this.data = data;
        this.dataMac = dataMac;
        this.emptyMac = emptyMac;
        this.macKey = new SecretKeySpec(key, 0, key.length, alg);
        this.mac = ProviderUtil.getMac(alg);
    }

    @Test
    public void update() throws Exception {
        if (algParamSpec != null) {
            mac.init(macKey, algParamSpec);
        } else {
            mac.init(macKey);
        }
        mac.update(data);
        byte[] result = mac.doFinal();

        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateOffsetLen() throws Exception {
        byte[] input = new byte[data.length + 4];
        System.arraycopy(data, 0, input, 2, data.length);
        mac.init(macKey, algParamSpec);
        mac.update(input, 2, data.length);
        byte[] result = mac.doFinal();

        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateParts() throws Exception {
        mac.init(macKey, algParamSpec);
        mac.update(data, 0, 2);
        mac.update(data, 2, 4);
        mac.update(data, 6, data.length - 6);
        mac.update(data, 2, 0);
        byte[] result = mac.doFinal();

        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateBytes() throws Exception {
        mac.init(macKey, algParamSpec);
        for (byte b : data) {
            mac.update(b);
        }
        byte[] result = mac.doFinal();

        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void emptyInput() throws Exception {
        mac.init(macKey, algParamSpec);
        byte[] result = mac.doFinal();
        Assert.assertArrayEquals(emptyMac, result);

        mac = ProviderUtil.getMac(this.alg);
        mac.init(macKey, algParamSpec);
        mac.update(new byte[0]);
        result = mac.doFinal();
        Assert.assertArrayEquals(emptyMac, result);

        mac = ProviderUtil.getMac(this.alg);
        mac.init(macKey, algParamSpec);
        mac.update(new byte[10], 0, 0);
        result = mac.doFinal();
        Assert.assertArrayEquals(emptyMac, result);
    }

    @Test
    public void updateByteBufferNotDirect() throws Exception {
        mac.init(macKey, algParamSpec);
        ByteBuffer bb = ByteBuffer.wrap(data);
        mac.update(bb);
        byte[] result = mac.doFinal();
        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void updateByteBufferDirect() throws Exception {
        mac.init(macKey, algParamSpec);
        ByteBuffer bb = TestUtil.directByteBuffer(data);
        mac.update(bb);
        byte[] result = mac.doFinal();
        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void reset() throws Exception {
        mac.init(macKey, algParamSpec);
        mac.update(data, 0, 5);
        mac.reset();
        mac.update(data);
        byte[] result = mac.doFinal();
        mac.reset();
        byte[] result2 = mac.doFinal();
        Assert.assertArrayEquals(dataMac, result);
        Assert.assertArrayEquals(emptyMac, result2);
    }

    @Test
    public void reuseAfterDoFinal() throws Exception {
        mac.init(macKey, algParamSpec);
        mac.doFinal();
        mac.update(data);
        byte[] result = mac.doFinal();
        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void testInitOtherProviderKey() throws Exception {
        KeyGenerator kg = KeyGenerator.getInstance("HmacSHA256");
        kg.init(128);
        SecretKey sk = kg.generateKey();

        mac.init(sk, algParamSpec);
    }

    @Test
    public void initAfterUpdate() throws Exception {
        mac.init(macKey, algParamSpec);
        mac.update(data, 0, 3);
        mac.init(macKey, algParamSpec);
        mac.update(data);
        byte[] result = mac.doFinal();
        Assert.assertArrayEquals(dataMac, result);
    }

    @Test
    public void testInitGeneratedKey() throws Exception {
        KeyGenerator kg = ProviderUtil.getKeyGenerator("HmacSha256");
        kg.init(128);
        SecretKey sk = kg.generateKey();

        mac.init(sk, algParamSpec);
    }

    @Test
    public void emptyKey() throws Exception {
        Assume.assumeTrue(alg.equals("HmacSHA256"));
        SecretKey sk = new SecretKeySpec(new byte[10], 0, 0, "Hmac");
        this.mac.init(sk);
        byte[] result = this.mac.doFinal();

        // SunJCE provider generated Mac for zero-length key.
        Assert.assertArrayEquals(TestUtil.hexStringToByteArray("B613679A0814D9EC772F95D778C35FC5FF1697C493715653C6C712144292C5AD"), result);
    }

    @Test
    public void getMacLength() throws Exception {
        this.mac.init(macKey, algParamSpec);
        Assert.assertEquals(dataMac.length, this.mac.getMacLength());
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void negativeAlgorithmParamSpec() throws Exception {
        this.mac.init(this.macKey, new ECGenParameterSpec("P256"));
    }

    @Test(expected = InvalidKeyException.class)
    public void negativeBadKey() throws Exception {
        this.mac.init(KeyUtil.getDummyEcPrivateKey(new byte[23]), algParamSpec);
    }

}
