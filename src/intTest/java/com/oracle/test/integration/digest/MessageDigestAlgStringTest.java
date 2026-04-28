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

package com.oracle.test.integration.digest;

import java.security.Provider;
import java.util.Arrays;
import java.util.Collection;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

/**
 * Test that provider includes expected aliases for MessageDigest algorithms.
 */
@RunWith(Parameterized.class)
public class MessageDigestAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> params() {
        return Arrays.asList(
            new Object[]{
                "SHA-1", new String[]{"SHA", "SHA1","1.3.14.3.2.26", "OID.1.3.14.3.2.26"}
            },
            new Object[]{
                "SHA-224", new String[]{"SHA224","2.16.840.1.101.3.4.2.4", "OID.2.16.840.1.101.3.4.2.4"}
            },
            new Object[]{
                "SHA-256", new String[]{"SHA256","2.16.840.1.101.3.4.2.1", "OID.2.16.840.1.101.3.4.2.1"}
            },
            new Object[]{
                "SHA-384", new String[]{"SHA384","2.16.840.1.101.3.4.2.2", "OID.2.16.840.1.101.3.4.2.2"}
            },
            new Object[]{
                "SHA-512", new String[]{"SHA512","2.16.840.1.101.3.4.2.3", "OID.2.16.840.1.101.3.4.2.3"}
            },
            new Object[]{
                "SHA3-224", new String[]{"2.16.840.1.101.3.4.2.7", "OID.2.16.840.1.101.3.4.2.7"}
            },
            new Object[]{
                    "SHA3-256", new String[]{"2.16.840.1.101.3.4.2.8", "OID.2.16.840.1.101.3.4.2.8"}
            },
            new Object[]{
                    "SHA3-384", new String[]{"2.16.840.1.101.3.4.2.9", "OID.2.16.840.1.101.3.4.2.9"}
            },
            new Object[]{
                    "SHA3-512", new String[]{"2.16.840.1.101.3.4.2.10", "OID.2.16.840.1.101.3.4.2.10"}
            }
        );
    }

    private final String alg;
    private final String[] aliases;

    public MessageDigestAlgStringTest(String alg, String[] aliases) {
        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("MessageDigest", alg);
        Assert.assertNotNull("Provider does not contain MessageDigest." + alg, service);
    }

    @Test
    public void aliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("MessageDigest", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("MessageDigest", a);
            Assert.assertNotNull("Provider does not contain MessageDigest." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for MessageDigest." + a, service.getClassName(), s.getClassName());
        }
    }
}
