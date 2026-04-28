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

import java.security.Provider;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.ProviderUtil;

@RunWith(Parameterized.class)
public class KeyPairGenAlgStringTest {

    @Parameterized.Parameters(name="{0}")
    public static Collection<Object[]> aliases() {
        List<Object[]> list = new ArrayList<>();
        return Arrays.asList(
                new Object[]{
                        "DH", new String[]{"DiffieHellman",
                                           "OID.1.2.840.113549.1.3.1", "1.2.840.113549.1.3.1"}
                },
                new Object[]{
                        "EC", new String[]{"EllipticCurve",
                                           "OID.1.2.840.10045.2.1", "1.2.840.10045.2.1"}
                },
                new Object[]{
                        "RSA", new String[]{"OID.1.2.840.113549.1.1", "1.2.840.113549.1.1",
                                            "OID.1.2.840.113549.1.1.1", "1.2.840.113549.1.1.1"}
                },
                new Object[]{
                        "RSASSA-PSS", new String[]{"PSS",
                                                   "OID.1.2.840.113549.1.1.10", "1.2.840.113549.1.1.10"}
                }
        );
    }

    private final String alg;
    private final String[] aliases;

    public KeyPairGenAlgStringTest(String alg, String[] aliases) {
        this.alg = alg;
        this.aliases = aliases;
    }

    @Test
    public void testAlgorithm() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("KeyPairGenerator", alg);
        Assert.assertNotNull("Provider does not contain KeyPairGenerator." + alg, service);
    }

    @Test
    public void testAliases() throws Exception {
        Provider provider = ProviderUtil.get();
        Provider.Service service = provider.getService("KeyPairGenerator", alg);

        for (String a : aliases) {
            Provider.Service s = provider.getService("KeyPairGenerator", a);
            Assert.assertNotNull("Provider does not contain KeyPairGenerator." + a, s);
            Assert.assertEquals("Provider returns incorrect impl for KeyPairGenerator." + a, service.getClassName(), s.getClassName());
        }
    }
}
