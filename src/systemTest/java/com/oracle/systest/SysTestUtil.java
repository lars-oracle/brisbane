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

package com.oracle.systest;

public class SysTestUtil {

    public static String getConfigId() {
        StringBuilder sb = new StringBuilder();

        if ((System.getProperty("jipher.openssl.useOsInstance") != null)) {
            sb.append("jipher_openssl_useOsInstance");
        }
        else if (System.getProperty("jipher.openssl.dir") != null) {
            sb.append("jipher_openssl_dir");
        }  else {
            sb.append("default");
        }

        String modulePath = System.getProperty("jdk.module.path");
        String classPath = System.getProperty("java.class.path");
        String regEx = "jipher-jce.*\\.jar";

        if (modulePath != null && modulePath.matches(regEx)) {
            sb.append("-modulepath");
        } else if (classPath != null && classPath.matches(regEx)) {
            sb.append("-classpath");
        }

        return sb.toString();
    }

    // True if e is a FIPS policy violation (message starts with "FIPS").
    // This function also checks that the expected FIPSPolicyException cause is present,
    // which is not strictly required for detecting the FIPS policy violation, but helps
    // preserve a useful stack trace in cases of debugging failures.
    private static boolean isDirectFipsException(Throwable e) {
        return e.getMessage().startsWith("FIPS") &&
                e.getCause() != null && e.getCause().getClass().getName().equals("com.oracle.jipher.internal.fips.FIPSPolicyException");
    }

    // True if e (or its immediate cause) indicates a FIPS policy violation.
    // (javax.crypto.KDF wraps an InvalidAlgorithmParameterException thrown by the
    // javax.crypto.KDFSpi implementation in a new InvalidAlgorithmParameterException with a
    // generic message, so check both e and e.getCause() to reliably detect FIPS violations.)
    public static boolean isFipsException(Exception e) {
        return isDirectFipsException(e) ||
                e.getCause() != null && isDirectFipsException(e.getCause());
    }
}
