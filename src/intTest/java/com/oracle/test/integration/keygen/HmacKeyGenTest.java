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
public class HmacKeyGenTest {

    private KeyGenerator kg;
    private final String alg;
    private final int defaultKeySize;

    @Parameterized.Parameters(name="{0}:{index}")
    public static Collection<Object[]> params() {
        return Arrays.asList(
                new Object[]{"HmacSHA1", 20},
                new Object[]{"HmacSHA224", 28},
                new Object[]{"HmacSHA256", 32},
                new Object[]{"HmacSHA384", 48},
                new Object[]{"HmacSHA512", 64}
        );

    }

    public HmacKeyGenTest(String alg, int defaultKeySize) {
        this.alg = alg;
        this.defaultKeySize = defaultKeySize;
    }

    @Before
    public void setUp() throws Exception {
        kg = ProviderUtil.getKeyGenerator(this.alg);
    }

    @Test
    public void generateDefault() throws Exception {
        doGenerate(this.defaultKeySize);
    }

    @Test
    public void initGenerateDefault() throws Exception {
        kg.init((SecureRandom) null);
        doGenerate(this.defaultKeySize);
    }


    @Test(expected = InvalidParameterException.class)
    public void initKeyBitsTooSmall() throws Exception {
        kg.init(39);
    }

    @Test(expected = InvalidAlgorithmParameterException.class)
    public void initParameters() throws Exception {
        kg.init(new RSAKeyGenParameterSpec(1024, null));
    }

    @Test
    public void initGenerate192() throws Exception {
        kg.init(192);
        doGenerate(24);
    }

    @Test
    public void initGenerate800() throws Exception {
        kg.init(800);
        doGenerate(100);
    }

    private void doGenerate(int expectedByteLen) throws Exception {
        SecretKey sk = kg.generateKey();
        assertEquals(expectedByteLen, sk.getEncoded().length);
        assertEquals(this.alg, sk.getAlgorithm());
    }

    @Test
    public void multipleUse() throws Exception {
        kg.init(256);
        doGenerate(32);
        doGenerate(32);
        kg.init(128);
        doGenerate(16);
        kg.init((SecureRandom) null);
        doGenerate(defaultKeySize);
    }
}
