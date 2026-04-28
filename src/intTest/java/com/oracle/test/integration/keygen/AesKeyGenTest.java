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
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Arrays;
import java.util.Collection;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class AesKeyGenTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> sizes() {
        return Arrays.asList(
            new Object[]{"AES", new int[]{128, 192, 256}},
            new Object[]{"AES_128/ECB/NoPadding", new int[]{128}},
            new Object[]{"AES_128/CBC/PKCS5Padding", new int[]{128}},
            new Object[]{"AES_128/CBC/PKCS7Padding", new int[]{128}},
            new Object[]{"AES_128/OFB/NoPadding", new int[]{128}},
            new Object[]{"AES_128/CFB/NoPadding", new int[]{128}},
            new Object[]{"AES_128/GCM/NoPadding", new int[]{128}},
            new Object[]{"AES_192/ECB/NoPadding", new int[]{192}},
            new Object[]{"AES_192/CBC/PKCS5Padding", new int[]{192}},
            new Object[]{"AES_192/CBC/PKCS7Padding", new int[]{192}},
            new Object[]{"AES_192/OFB/NoPadding", new int[]{192}},
            new Object[]{"AES_192/CFB/NoPadding", new int[]{192}},
            new Object[]{"AES_192/GCM/NoPadding", new int[]{192}},
            new Object[]{"AES_256/ECB/NoPadding", new int[]{256}},
            new Object[]{"AES_256/CBC/PKCS5Padding", new int[]{256}},
            new Object[]{"AES_256/CBC/PKCS7Padding", new int[]{256}},
            new Object[]{"AES_256/OFB/NoPadding", new int[]{256}},
            new Object[]{"AES_256/CFB/NoPadding", new int[]{256}},
            new Object[]{"AES_256/GCM/NoPadding", new int[]{256}}
        );
    }

    private final String alg;
    private final int default_size;
    private final int[] valid_sizes;
    private KeyGenerator kg;

    // Takes an algorithm and list of valid key sizes, default key size listed last.
    public AesKeyGenTest(String alg, int[] sizes) {
        this.alg = alg;
        this.default_size = sizes[sizes.length - 1];
        this.valid_sizes = sizes;
        this.kg = null;
    }

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator(alg);
    }

    @Test
    public void initGenerateValidLens() throws Exception {
        for (int size : valid_sizes) {
            doInitGenerate(size);
        }
    }

    @Test
    public void initGenerateDefault() throws Exception {
        kg.init((SecureRandom) null);
        genCheck(default_size / 8);
    }

    private void doInitGenerate(int keyBits) throws Exception {
        kg.init(keyBits);
        genCheck(keyBits / 8);
    }

    private void genCheck(int expectedByteLen) {
        SecretKey sk = kg.generateKey();
        assertEquals(expectedByteLen, sk.getEncoded().length);
        assertEquals("AES", sk.getAlgorithm());
    }

    @Test(expected = InvalidParameterException.class)
    public void initInvalidLenLong() throws Exception {
        kg.init(512);
    }
    @Test(expected = InvalidParameterException.class)
    public void initInvalidLenShort() throws Exception {
        kg.init(32);
    }

    @Test(expected = InvalidParameterException.class)
    public void initInvalidLenOther() throws Exception {
        int[] sizes = {128, 192, 256, 200};
        for (int size: sizes) {
             // If this is not a valid key size for this algorithm
             if (Arrays.binarySearch(valid_sizes, size) < 0) {
                 kg.init(size);
                 break;
             }
        }
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initAlgSpec() throws Exception {
        kg.init(new RSAKeyGenParameterSpec(2048, BigInteger.valueOf(3)));
    }

    @Test
    public void generateWithoutInit() throws Exception {
        genCheck(default_size / 8);
    }

    @Test
    public void multipleUse() throws Exception {
        doInitGenerate(default_size);
        genCheck(default_size / 8);
        doInitGenerate(valid_sizes[valid_sizes.length - 1]);
    }
}
