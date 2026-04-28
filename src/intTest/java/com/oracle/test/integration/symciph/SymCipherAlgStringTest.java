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

package com.oracle.test.integration.symciph;

import java.security.Provider;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

@RunWith(Parameterized.class)
public class SymCipherAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> aliases() {
        return Arrays.asList(
                new Object[]{
                        "AES", new String[]{"Rijndael", "OID.2.16.840.1.101.3.4.1", "2.16.840.1.101.3.4.1"}
                },
                new Object[]{
                        "AES_128/ECB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.1", "2.16.840.1.101.3.4.1.1"}
                },
                new Object[]{
                        "AES_128/CBC/PKCS5Padding", new String[]{"AES_128/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2"}
                },
                new Object[]{
                        "AES_128/OFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3"}
                },
                new Object[]{
                        "AES_128/CFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4"}
                },
                new Object[]{
                        "AES_128/GCM/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6"}
                },
                new Object[]{
                        "AES_192/ECB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.21", "2.16.840.1.101.3.4.1.21"}
                },
                new Object[]{
                        "AES_192/CBC/PKCS5Padding", new String[]{"AES_192/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22"}
                },
                new Object[]{
                        "AES_192/OFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23"}
                },
                new Object[]{
                        "AES_192/CFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24"}
                },
                new Object[]{
                        "AES_192/GCM/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26"}
                },
                new Object[]{
                        "AES_256/ECB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.41", "2.16.840.1.101.3.4.1.41"}
                },
                new Object[]{
                        "AES_256/CBC/PKCS5Padding", new String[]{"AES_256/CBC/PKCS7Padding", "OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42"}
                },
                new Object[]{
                        "AES_256/OFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43"}
                },
                new Object[]{
                        "AES_256/CFB/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44"}
                },
                new Object[]{
                        "AES_256/GCM/NoPadding", new String[]{"OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46"}
                },
                new Object[]{
                        "AES/KW/NoPadding", new String[]{"AESWrap", "AES-KW"}
                },
                new Object[]{
                        "AES_128/KW/NoPadding", new String[]{"AESWrap_128", "OID.2.16.840.1.101.3.4.1.5", "2.16.840.1.101.3.4.1.5"}
                },
                new Object[]{
                        "AES_192/KW/NoPadding", new String[]{"AESWrap_192", "OID. 2.16.840.1.101.3.4.1.25", "2.16.840.1.101.3.4.1.25"}
                },
                new Object[]{
                        "AES_256/KW/NoPadding", new String[]{"AESWrap_256", "OID.2.16.840.1.101.3.4.1.45", "2.16.840.1.101.3.4.1.45"}
                },
                new Object[]{
                        "AES/KWP/NoPadding", new String[]{"AESWrapPad", "AES-KWP"}
                },
                new Object[]{
                        "AES_128/KWP/NoPadding", new String[]{"AESWrapPad_128", "OID.2.16.840.1.101.3.4.1.8", "2.16.840.1.101.3.4.1.8"}
                },
                new Object[]{
                        "AES_192/KWP/NoPadding", new String[]{"AESWrapPad_192", "OID.2.16.840.1.101.3.4.1.28", "2.16.840.1.101.3.4.1.28"}
                },
                new Object[]{
                        "AES_256/KWP/NoPadding", new String[]{"AESWrapPad_256", "OID.2.16.840.1.101.3.4.1.48", "2.16.840.1.101.3.4.1.48"}
                },
                new Object[]{
                        "DESede", new String[]{"TripleDES"}
                },
                new Object[]{
                        "DESede/CBC/PKCS5Padding", new String[]{"DESede/CBC/PKCS7Padding", "OID.1.2.840.113549.3.7", "1.2.840.113549.3.7"}
                }
        );
    }

    private final String alg;
    private final String[] aliases;

    public SymCipherAlgStringTest(String alg, String[] aliases) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().startsWith("DESEDE"));
        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("Cipher", alg);
        Assert.assertNotNull("Provider does not contain Cipher." + alg, service);
    }

    @Test
    public void testAliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("Cipher", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("Cipher", a);
            Assert.assertNotNull("Provider does not contain Cipher." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for Cipher." + a, service.getClassName(), s.getClassName());
        }
    }
}
