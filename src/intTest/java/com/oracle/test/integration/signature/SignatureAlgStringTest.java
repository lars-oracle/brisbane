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

package com.oracle.test.integration.signature;

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
public class SignatureAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> aliases() {
        return Arrays.asList(
            new Object[]{
                    "SHA1withRSA", new String[]{"OID.1.2.840.113549.1.1.5", "1.2.840.113549.1.1.5",
                                                "OID.1.3.14.3.2.29", "1.3.14.3.2.29"}
            },
            new Object[]{
                    "SHA224withRSA", new String[]{"OID.1.2.840.113549.1.1.14", "1.2.840.113549.1.1.14"}
            },
            new Object[]{
                    "SHA256withRSA", new String[]{"OID.1.2.840.113549.1.1.11", "1.2.840.113549.1.1.11"}
            },
            new Object[]{
                    "SHA384withRSA", new String[]{"OID.1.2.840.113549.1.1.12", "1.2.840.113549.1.1.12"}
            },
            new Object[]{
                    "SHA512withRSA", new String[]{"OID.1.2.840.113549.1.1.13", "1.2.840.113549.1.1.13"}
            },
            new Object[]{
                    "SHA1withECDSA", new String[]{"1.2.840.10045.4.1", "OID.1.2.840.10045.4.1"}
            },
            new Object[]{
                    "SHA224withECDSA", new String[]{"1.2.840.10045.4.3.1", "OID.1.2.840.10045.4.3.1"}
            },
            new Object[]{
                    "SHA256withECDSA", new String[]{"1.2.840.10045.4.3.2", "OID.1.2.840.10045.4.3.2"}
            },
            new Object[]{
                    "SHA384withECDSA", new String[]{"1.2.840.10045.4.3.3", "OID.1.2.840.10045.4.3.3"}
            },
            new Object[]{
                    "SHA512withECDSA", new String[]{"1.2.840.10045.4.3.4", "OID.1.2.840.10045.4.3.4"}
            },
            new Object[]{
                    "NONEwithDSA", new String[]{"RawDSA"}
            },
            new Object[]{
                    "SHA1withDSA", new String[]{"DSA", "DSS", "SHA/DSA", "SHA-1/DSA", "SHA1/DSA",
                                                "SHAwithDSA", "DSAWithSHA1",
                                                "OID.1.2.840.10040.4.3", "1.2.840.10040.4.3",
                                                "OID.1.3.14.3.2.13", "1.3.14.3.2.13",
                                                "OID.1.3.14.3.2.27", "1.3.14.3.2.27"}
            },
            new Object[]{
                    "SHA224withDSA", new String[]{"2.16.840.1.101.3.4.3.1", "OID.2.16.840.1.101.3.4.3.1"}
            },
            new Object[]{
                    "SHA256withDSA", new String[]{"2.16.840.1.101.3.4.3.2", "OID.2.16.840.1.101.3.4.3.2"}
            },
            new Object[]{
                    "SHA384withDSA", new String[]{"OID.2.16.840.1.101.3.4.3.3", "2.16.840.1.101.3.4.3.3"}
            },
            new Object[]{
                    "SHA512withDSA", new String[]{"OID.2.16.840.1.101.3.4.3.4", "2.16.840.1.101.3.4.3.4"}
            },
            new Object[]{
                    "SHA224withRSAandMGF1", new String[]{"SHA224withRSA/PSS"}
            },
            new Object[]{
                    "SHA256withRSAandMGF1", new String[]{"SHA256withRSA/PSS"}
            },
            new Object[]{
                    "SHA384withRSAandMGF1", new String[]{"SHA384withRSA/PSS"}
            },
            new Object[]{
                    "SHA512withRSAandMGF1", new String[]{"SHA512withRSA/PSS"}
            },
            new Object[]{
                    "RSASSA-PSS", new String[]{"PSS",
                                               "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10"}
            }
        );
    }

    private final String alg;
    private final String[] aliases;

    public SignatureAlgStringTest(String alg, String[] aliases) {
        Assume.assumeTrue(FipsProviderInfoUtil.isSHA1DigestSignatureSupported() || !alg.toUpperCase().contains("SHA1"));
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported() ||
                !(alg.toUpperCase().contains("DSA") && !alg.toUpperCase().contains("ECDSA")));
        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("Signature", alg);
        Assert.assertNotNull("Provider does not contain Signature." + alg, service);
    }

    @Test
    public void testAliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("Signature", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("Signature", a);
            Assert.assertNotNull("Provider does not contain Signature." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for Signature." + a, service.getClassName(), s.getClassName());
        }
    }
}
