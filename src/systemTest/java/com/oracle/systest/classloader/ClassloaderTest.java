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

package com.oracle.systest.classloader;

import java.io.File;
import java.net.URL;
import java.net.URLClassLoader;
import java.nio.file.Paths;
import java.security.Provider;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;

import org.junit.BeforeClass;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;
import org.junit.runners.Parameterized.Parameters;

@RunWith(Parameterized.class)
public abstract class ClassloaderTest {

    static Provider getProvider() throws Exception {
        String[] jars = System.getProperty("provider.jar.path").split(File.pathSeparator);
        URL[] urls = new URL[jars.length];
        for (int i = 0; i < urls.length; i++) {
            urls[i] =  Paths.get(jars[i]).toUri().toURL();
        }
        ClassLoader cLoader = URLClassLoader.newInstance(urls);
        return (Provider) cLoader.loadClass("com.oracle.jipher.provider.JipherJCE").getDeclaredConstructor().newInstance();
    }

    /**
     * We use the parameters to name the test according to the library.
     */
    @Parameters(name = "{0}")
    public static Collection<Object[]> configParams() {
        List<Object[]> l = new ArrayList<>();
        l.add(new Object[]{"CFG=" + getNativeConfigId()});
        return l;
    }

    static Provider jipherJce;
    static Provider jipherJce2;

    @BeforeClass
    public static void createClassloaders() throws Exception {

        String systemPropertyList = System.getProperty("1stPropertyList");
        setSystemProperties(systemPropertyList);

        System.out.println("Creating 1st classloader; with system properties:" + getSystemPropertyNames(systemPropertyList));
        jipherJce = getProvider();

        systemPropertyList = System.getProperty("2ndPropertyList");
        setSystemProperties(systemPropertyList);

        System.out.println("Creating 2nd classloader; with system properties:" + getSystemPropertyNames(systemPropertyList));
        jipherJce2 = getProvider();
    }

    public ClassloaderTest(String configName) {
        // Nothing to do
    }

    public static String getNativeConfigId() {
        return getSystemPropertyNames(System.getProperty("1stPropertyList")).toString() + "-" +
                getSystemPropertyNames(System.getProperty("2ndPropertyList")).toString();
    }

    public static List<String> getSystemPropertyNames(String systemPropertyList) {
        List<String> list = new ArrayList<>();
        for (String systemProperty : systemPropertyList.split(";")) {
            if (!systemProperty.isEmpty()) {
                list.add(systemProperty.split("=")[0]);
            }
        }
        return list;
    }

    public static void setSystemProperties(String systemPropertyList) {
        for (String systemProperty : systemPropertyList.split(";")) {
            if (!systemProperty.isEmpty()) {
                String[] element = systemProperty.split("=");
                System.setProperty(element[0], element[1]);
            }
        }
    }
}
