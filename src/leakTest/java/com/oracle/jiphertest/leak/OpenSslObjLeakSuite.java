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

package com.oracle.jiphertest.leak;

import java.security.Provider;
import java.security.Security;
import java.util.Arrays;

import org.junit.platform.suite.api.AfterSuite;
import org.junit.platform.suite.api.BeforeSuite;
import org.junit.platform.suite.api.IncludeClassNamePatterns;
import org.junit.platform.suite.api.SelectPackages;
import org.junit.platform.suite.api.Suite;

import com.oracle.jiphertest.leak.util.JavaxCryptoUtil;
import com.oracle.jiphertest.leak.util.NativeObjectUsageMonitor;
import com.oracle.jiphertest.leak.util.PreFetchUtil;
import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.X509FactoryUtil;

import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.fail;

@Suite
@SelectPackages("com.oracle.test.integration")
@IncludeClassNamePatterns({".*Test.*"}) // This is necessary to include inner classes such as 'SignatureTest$NoDigest'
public class OpenSslObjLeakSuite {

    static final private long ONE_SECOND = 1_000; // in milliseconds

    @BeforeSuite
    public static void setup() {
        if (EnvUtil.isOracleJdk()) {
            // For Oracle JDKs, the first time a security provider is used to provide an algorithm for an engine class
            // in the javax.crypto package the provider is authenticated which causes the javax.crypto.JarVerifier
            // class to be loaded, and it's static initializer run.  The static initializer loads the set of JCE Code
            // Signing CA certificates.
            //
            // If JipherJCE is registered, with the highest priority, when the javax.crypto.JarVerifier class's
            // static initializer is run then JipherJCE will be used to load the public key of each of the
            // JCE Code Signing CA certificates. Each public key will be backed by an OpenSSL PKEY.
            //
            // If the public key, from JCE Code Signing CA certificate, is used to verify the signature on another
            // certificate then it will be stored as the 'verifiedPublicKey' of that certificate.
            //
            // This results in the public key (which is backed by an OpenSSL PKEY) being referenced from several
            // 'caches':
            // (1) The providerValidator & exemptValidator static members of the javax.crypto.JarVerifier class
            //     are both a SimpleValidator objects that reference the JCE Code Signing CA certificates though their
            //     trustedX500Principals Map and trustedCerts Collection
            // (2) The java.lang.ClassLoader (AppClassLoader) class's 'package2Certs' Map which maps packages to
            //     certificates. Any package verified with a certificate issued by one of the JCE Code Signing CA
            //     certificates will map to a certificate whose 'verifiedPublicKey' is the public key from a JCE Code
            //     Signing CA certificate.
            // (3) The java.security.SecureClassLoader class's 'pdcache' Map which maps the CodeSource to a
            //     ProtectionDomain. The CodeSource contains a list of certificates. Any certificate verified by one o
            //     the JCE Code Signing CA certificates will have its 'verifiedPublicKey' set to the public key from a
            //     JCE Code Signing CA certificate.
            // (4) The java.util.jar.JarVerifier class's 'verifiedSigners' hash table that maps the names of Jar entries
            //     to the code signers that verified them. The CodeSigner contains a list of certificates.
            //     Any certificate verified by one of the JCE Code Signing CA certificates will have its 'verifiedPublicKey'
            //     set to the public key from a JCE Code Signing CA certificate.
            //
            // While it is possible to 'clear' some of these 'caches' using reflection:
            // (1) Requires: --add-opens=java.base/javax.crypto=ALL-UNNAMED
            //       Class<?> cls = Class.forName("javax.crypto.JarVerifier");
            //       for (String fieldName : new String[]{"providerValidator", "exemptValidator"}) {
            //          Field field = cls.getDeclaredField(fieldName);
            //          field.setAccessible(true);
            //          field.set(null, null);
            //       }
            // (2) Requires: --add-opens=java.base/java.lang=ALL-UNNAMED
            //        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            //        Class<?> cls = Class.forName("java.lang.ClassLoader");
            //        Method m = cls.getDeclaredMethod("resetArchivedStates");
            //        m.setAccessible(true);
            //        m.invoke(classLoader);
            // (3) Requires: --add-opens=java.base/java.security=ALL-UNNAMED
            //        ClassLoader classLoader = Thread.currentThread().getContextClassLoader();
            //        Class<?> cls = Class.forName("java.security.SecureClassLoader");
            //        Method m = cls.getDeclaredMethod("resetArchivedStates");
            //        m.setAccessible(true);
            //        m.invoke(classLoader);
            // (4) ???
            //
            // It is less intrusive to simply ensure that the javax.crypto.JarVerifier class's static initialiser
            // is run before JipherJCE has been registered as a security provider. Doing so ensures that the
            // public keys of JCE Code Signing CA certificates are provided by a JDK provider and thus are not backed
            // by a PKEY.
            assertTrue(Arrays.stream(Security.getProviders()).map(Provider::getName).noneMatch("JipherJCE"::equals));
            JavaxCryptoUtil.loadJarVerifierClass();
        }

        // The memory segments of Cipher, Kdf, Mac & Md algorithm's pre-fetched by JipherJCE are stored in global scope
        // arenas that are not released until the JVM exits. Trigger prefetching before activating the
        // native object usage monitor so that these allocations will not be recorded and reported as memory leaks.
        PreFetchUtil.triggerPrefetch();

        // Activate the native object usage monitor
        NativeObjectUsageMonitor.activate();
    }

    @AfterSuite
    public static void tearDown() {
        // Clear the certificate cache to trigger release of PKEY's that back certificate public keys.
        X509FactoryUtil.clearCertCache();

        // Clear the adapter layer object pools.
        NativeObjectUsageMonitor.clearObjectPools();

        // Trigger garbage collection to recover memory associated with unreachable objects.
        int retryCount = 0;
        do {
            try { Thread.sleep(ONE_SECOND * retryCount); } catch (Exception ignored) {}
            System.gc();
        } while (NativeObjectUsageMonitor.isTrackingLiveObjects() && retryCount++ < 3);

        // Deactivate the native object usage monitor
        NativeObjectUsageMonitor.deactivate();

        // Report any errors detected by the native object usage monitor
        if (NativeObjectUsageMonitor.detectedErrors()) {
            fail("OpenSSL object usage error detected",
                    new Error("OBJECT USAGE ERRORS:\n" + NativeObjectUsageMonitor.reportErrors()));
        }

        // Report any live objects still tracked by the native object usage monitor
        if (NativeObjectUsageMonitor.isTrackingLiveObjects()) {
            fail("OpenSSL object leak detected",
                    new Error("LIVE OBJECTS:\n" + NativeObjectUsageMonitor.reportLiveObjects()));
        }

        // Reset the native object usage monitor (clears errors and forgets about tracked objects).
        NativeObjectUsageMonitor.reset();
    }
}
