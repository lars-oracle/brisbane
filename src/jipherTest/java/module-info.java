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

module com.oracle.jiphertest.other {
    exports com.oracle.jiphertest.helpers;
    exports com.oracle.jiphertest.model;
    exports com.oracle.jiphertest.testdata;
    exports com.oracle.jiphertest.util;

    // The com.oracle.jiphertest.util.ProviderUtil class creates an instance of com.oracle.jipher.provider.JipherJCE to
    // dynamically register it as a java security provider.
    // The com.oracle.jiphertest.util.FipsProviderInfoUtil class creates an instance of
    // com.oracle.jipher.provider.JipherJCE from which it can query information about the OpenSSL FIPS provider version.
    // The com.oracle.systest.classloader.CipherTest system test uses com.oracle.jiphertest.testdata to load test data,
    // but it does NOT list jipher-jce on the classpath because it uses a URLClassLoader to load the jipher-jce JAR.
    // Consequently, the following 'requires' statement is 'static' to indicate that the dependency is required
    // at compile time but is optional at run time.
    requires static com.oracle.jipher;

    // testdata uses gson
    requires com.google.gson;
    // Allow com.google.gson to use reflection on the classes in this module's classes. Prevents:
    //      "module com.oracle.jiphertest.other does not opens com.oracle.jiphertest.testdata" to module com.google.gson
    opens com.oracle.jiphertest.testdata to com.google.gson;

    // com.oracle.jiphertest.helpers.TlsServer used org.junit.Assert
    requires junit; // Automatic module from junit:junit
}
