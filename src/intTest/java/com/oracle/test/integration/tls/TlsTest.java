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

package com.oracle.test.integration.tls;

import java.io.InputStream;
import java.io.OutputStream;
import java.security.Security;
import java.util.Arrays;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSession;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;

import org.junit.After;
import org.junit.AfterClass;
import org.junit.Before;
import org.junit.BeforeClass;
import org.junit.Test;

import com.oracle.jiphertest.helpers.TlsServer;
import com.oracle.jiphertest.helpers.TlsSetup;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.X509FactoryUtil;

import static com.oracle.jiphertest.helpers.TlsSetup.genTestData;
import static com.oracle.jiphertest.helpers.TlsSetup.readData;
import static org.junit.Assert.assertArrayEquals;
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertTrue;
import static org.junit.Assume.assumeTrue;

public class TlsTest {

    private static final int TESTDATA_SIZE = 36 * 1024;
    private static final byte[] TEST_DATA = genTestData(TESTDATA_SIZE);

    private static TlsServer serverJdk;
    private static TlsServer serverJipher;

    static boolean isTls13Supported;

    @BeforeClass
    public static void startServers() throws Exception {
        SSLSocket s = (SSLSocket) SSLSocketFactory.getDefault().createSocket();
        isTls13Supported = Arrays.asList(s.getSupportedProtocols()).contains("TLSv1.3");

        serverJdk = new TlsServer(TlsSetup.ProviderConfig.JDK_JSSE, true);
        serverJipher = new TlsServer(TlsSetup.ProviderConfig.JIPHER_JSSE, true);
        serverJdk.startServer();
        serverJipher.startServer();
    }

    @AfterClass
    public static void stopServers() throws InterruptedException {
        serverJdk.stopServer();
        serverJipher.stopServer();
    }

    @Before
    public void setUp() throws Exception {
        X509FactoryUtil.clearCertCache();
    }

    SSLSocketFactory getSocketFactory() throws Exception {
        SSLContext ctx = TlsSetup.getSSLContext("client");
        return ctx.getSocketFactory();
    }

    @After
    public void tearDown() throws Exception {
        Security.removeProvider(ProviderUtil.get().getName());
        X509FactoryUtil.clearCertCache();
    }

    @Test
    public void jipherClientJdkServerTLSV12() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        SSLSocketFactory sf = getSocketFactory();
        for (String cipherSuite : TlsSetup.ciphersuitesV12Subset()) {
            doTest(sf, serverJdk, "TLSv1.2", cipherSuite);
        }
    }

    @Test
    public void jipherClientJipherServerTLSV12() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        SSLSocketFactory sf = getSocketFactory();

        for (String cipherSuite : TlsSetup.ciphersuitesV12()) {
            doTest(sf, serverJipher, "TLSv1.2", cipherSuite);
        }
    }

    @Test
    public void jdkClientJipherServerTLSV12() throws Exception {
        SSLSocketFactory sf = getSocketFactory();
        for (String cipherSuite : TlsSetup.ciphersuitesV12Subset()) {
            doTest(sf, serverJipher, "TLSv1.2", cipherSuite);
        }
    }

    @Test
    public void jipherClientJdkServerTLSV13() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        SSLSocketFactory sf = getSocketFactory();
        for (String cipherSuite : TlsSetup.ciphersuitesV13()) {
            doTest(sf, serverJdk, "TLSv1.3", cipherSuite);
        }
    }

    @Test
    public void jipherClientJipherServerTLSV13() throws Exception {
        Security.insertProviderAt(ProviderUtil.get(), 1);
        SSLSocketFactory sf = getSocketFactory();

        for (String cipherSuite : TlsSetup.ciphersuitesV13()) {
            doTest(sf, serverJipher, "TLSv1.3", cipherSuite);
        }
    }

    @Test
    public void jdkClientJipherServerTLSV13() throws Exception {
        SSLSocketFactory sf = getSocketFactory();
        for (String cipherSuite : TlsSetup.ciphersuitesV13()) {
            doTest(sf, serverJipher, "TLSv1.3", cipherSuite);
        }
    }

    private void doTest(SSLSocketFactory sf, TlsServer server, String proto, String cipherSuite) throws Exception {
        if (proto.equals("TLSv1.3")) {
            assumeTrue("TLSv1.3 not supported by JDK", isTls13Supported);
        }
        SSLSocket s = (SSLSocket) sf.createSocket("localhost", server.getPort());
        s.setEnabledProtocols(new String[]{proto});
        s.setEnabledCipherSuites(new String[]{cipherSuite});
        InputStream is = s.getInputStream();
        OutputStream os = s.getOutputStream();
        os.write(TEST_DATA);
        os.flush();
        byte[] receivedData = readData(is, TESTDATA_SIZE);
        s.close();
        SSLSession session = s.getSession();
        checkCipherSuite(cipherSuite, session.getCipherSuite());
        assertEquals(proto, session.getProtocol());
        assertArrayEquals(TEST_DATA, receivedData);
        assertTrue(server.getResult());
    }

    private void checkCipherSuite(String cipherSuite, String sessionSuite) {
        assertEquals(cipherSuite.substring(4), sessionSuite.substring(4));
    }
}
