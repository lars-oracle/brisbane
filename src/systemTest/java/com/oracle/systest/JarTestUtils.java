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

import java.net.JarURLConnection;
import java.net.URL;
import java.nio.file.Paths;
import java.security.CodeSource;
import java.util.Set;
import java.util.jar.JarFile;
import java.util.zip.ZipEntry;

import static java.util.stream.Collectors.toSet;
import static org.junit.Assert.assertNotNull;

public class JarTestUtils {

    protected static JarFile getJarFile(Class cls) throws Exception {
        CodeSource cs = cls.getProtectionDomain().getCodeSource();
        assertNotNull(cs);
        URL url = cs.getLocation();
        assertNotNull(url);
        url = Paths.get("jar:" + url.toString() + "!/").toUri().toURL();
        return ((JarURLConnection) url.openConnection()).getJarFile();
    }

    protected static Set<String> getJarEntrySet(Class cls) throws Exception {
        return getJarEntrySet(getJarFile(cls));
    }

    protected static Set<String> getJarEntrySet(JarFile jf) throws Exception {
        return jf.stream().map(ZipEntry::getName).collect(toSet());
    }
}
