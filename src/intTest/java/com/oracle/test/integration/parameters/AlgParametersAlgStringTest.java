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

package com.oracle.test.integration.parameters;

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
public class AlgParametersAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> aliases() {
        return Arrays.asList(
                new Object[]{
                        "AES", new String[] {
                        "OID.2.16.840.1.101.3.4.1", "2.16.840.1.101.3.4.1",
                        "OID.2.16.840.1.101.3.4.1.2", "2.16.840.1.101.3.4.1.2",
                        "OID.2.16.840.1.101.3.4.1.3", "2.16.840.1.101.3.4.1.3",
                        "OID.2.16.840.1.101.3.4.1.4", "2.16.840.1.101.3.4.1.4",
                        "OID.2.16.840.1.101.3.4.1.6", "2.16.840.1.101.3.4.1.6",
                        "OID.2.16.840.1.101.3.4.1.22", "2.16.840.1.101.3.4.1.22",
                        "OID.2.16.840.1.101.3.4.1.23", "2.16.840.1.101.3.4.1.23",
                        "OID.2.16.840.1.101.3.4.1.24", "2.16.840.1.101.3.4.1.24",
                        "OID.2.16.840.1.101.3.4.1.26", "2.16.840.1.101.3.4.1.26",
                        "OID.2.16.840.1.101.3.4.1.42", "2.16.840.1.101.3.4.1.42",
                        "OID.2.16.840.1.101.3.4.1.43", "2.16.840.1.101.3.4.1.43",
                        "OID.2.16.840.1.101.3.4.1.44", "2.16.840.1.101.3.4.1.44",
                        "OID.2.16.840.1.101.3.4.1.46", "2.16.840.1.101.3.4.1.46"}
                },
                new Object[]{
                        "DESede", new String[]{
                        "OID.1.2.840.113549.3.7", "1.2.840.113549.3.7"}
                },
                new Object[]{
                        "DH", new String[]{
                        "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1"}
                },
                new Object[]{
                        "EC", new String[]{
                        "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"}
                },
                new Object[]{
                        "OAEP", new String[]{
                        "OID.1.2.840.113549.1.1.7", "1.2.840.113549.1.1.7"}
                },
                new Object[]{
                        "PBES2", new String[]{
                        "OID.1.2.840.113549.1.5.13", " 1.2.840.113549.1.5.13"}
                },
                new Object[]{
                        "RSASSA-PSS", new String[]{
                        "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10"}
                }
        );
    }

    private final String alg;
    private final String[] aliases;

    public AlgParametersAlgStringTest(String alg, String[] aliases) {
        Assume.assumeTrue(FipsProviderInfoUtil.isDESEDESupported() || !alg.toUpperCase().contains("DESEDE"));
        Assume.assumeTrue(FipsProviderInfoUtil.isDSASupported() || !alg.toUpperCase().contains("DSA"));
        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("AlgorithmParameters", alg);
        Assert.assertNotNull(service);
    }

    @Test
    public void testAliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("AlgorithmParameters", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("AlgorithmParameters", a);
            Assert.assertNotNull("Provider does not contain AlgorithmParameters." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for AlgorithmParameters." + a, service.getClassName(), s.getClassName());
        }
    }
}
