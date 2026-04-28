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

package com.oracle.test.integration.keystore;

import java.io.InputStream;
import java.security.KeyStore;
import java.security.Provider;
import java.security.Security;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collection;
import java.util.Enumeration;
import java.util.List;

import org.junit.After;
import org.junit.Assume;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.testdata.TestData;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static org.junit.Assert.assertNotNull;

@RunWith(Parameterized.class)
public class Rfc9879Test {
    static private final List<String> REQUIRED_PROVIDER_NAMES = Arrays.asList(new String[]{"JipherJCE", "SUN"});
    static private final List<String> MAC_NAMES = Arrays.asList(new String[]{"HmacSHA1", "HmacSHA224", "HmacSHA256", "HmacSHA384", "HmacSHA512"});
    static private final char[] PASSWORD = "password".toCharArray();

    private Provider[] providers;
    private final String filename;

    public Rfc9879Test(String filename) {
        Assume.assumeTrue("At present RFC-9879 is only supported on JDK 26 and later", EnvUtil.isJdk26Plus());
        this.filename = filename;
    }

    @Parameterized.Parameters(name="{0} ({index})")
    public static Collection<Object[]> params() {
        ArrayList<Object[]> params = new ArrayList<>();
        for (String keyStoreProviderName : Arrays.asList(new String[]{"SUN", "OpenSSL"})) {
            for (String macName : MAC_NAMES) {
                params.add(new Object[]{keyStoreProviderName + ".pbmac1." + macName.toLowerCase() + ".keystore.p12"});
            }
        }

        return params;
    }

    @Before
    public void beforeMethod() {
        this.providers = Security.getProviders();

        if (Arrays.stream(providers).map(Provider::getName).noneMatch(ProviderUtil.get().getName()::equals)) {
            Security.insertProviderAt(ProviderUtil.get(), 1);
        }
        for (Provider provider : this.providers) {
            if (!REQUIRED_PROVIDER_NAMES.contains(provider.getName())) {
                Security.removeProvider(provider.getName());
            }
        }
    }

    @After
    public void tearDown()  {
        if (Arrays.stream(providers).map(Provider::getName).noneMatch(ProviderUtil.get().getName()::equals)) {
            Security.removeProvider(ProviderUtil.get().getName());
        }
        for (int index = 0; index < providers.length; index++) {
            Provider provider = providers[index];
            int position = index + 1;
            if (!REQUIRED_PROVIDER_NAMES.contains(provider.getName())) {
                Security.insertProviderAt(provider, position);
            }
        }
    }

    @Test
    public void testLoad() throws Exception {
        KeyStore ks = KeyStore.getInstance("PKCS12");

        InputStream testIn = TestData.getResourceAsStream("/keystore/"+ this.filename);
        assertNotNull(testIn);
        ks.load(testIn, PASSWORD);

        for (Enumeration<String> e = ks.aliases(); e.hasMoreElements();) {
            String alias = e.nextElement();
            if (ks.isKeyEntry(alias)) {
                assertNotNull(ks.getKey(alias, PASSWORD));
            } else {
                assertNotNull(ks.getCertificate(alias));
            }
        }
    }
}
