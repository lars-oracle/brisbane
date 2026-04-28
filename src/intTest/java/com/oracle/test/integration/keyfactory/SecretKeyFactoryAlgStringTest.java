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

package com.oracle.test.integration.keyfactory;

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
public class SecretKeyFactoryAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> aliases() {
        return Arrays.asList(
            new Object[]{
                    "DESede", new String[] {"TripleDES"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA1", new String[]{"PBKDF2WithSHA1", "OID.1.2.840.113549.1.5.12", "1.2.840.113549.1.5.12"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA224", new String[]{"PBKDF2WithSHA224"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA256", new String[]{"PBKDF2WithSHA256"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA384", new String[]{"PBKDF2WithSHA384"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA512", new String[]{"PBKDF2WithSHA512"}
            },
            new Object[]{
                    "PBKDF2WithHmacSHA1and8BIT", new String[]{"PBKDF2withASCII", "PBKDF2with8BIT"}
            }
        );
    }

    private final String alg;
    private final String[] aliases;

    public SecretKeyFactoryAlgStringTest(String alg, String[] aliases) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported() || !alg.equals("DSA"));
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().contains("DESEDE"));

        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("SecretKeyFactory", alg);
        Assert.assertNotNull(service);
    }

    @Test
    public void testAliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("SecretKeyFactory", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("SecretKeyFactory", a);
            Assert.assertNotNull("Provider does not contain SecretKeyFactory." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for SecretKeyFactory." + a, service.getClassName(), s.getClassName());
        }
    }
}
