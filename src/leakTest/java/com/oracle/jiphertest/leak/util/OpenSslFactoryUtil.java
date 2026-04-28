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

package com.oracle.jiphertest.leak.util;

import java.lang.reflect.Method;

import com.oracle.jipher.internal.openssl.OpenSsl;
import com.oracle.jipher.provider.JipherJCE;

public class OpenSslFactoryUtil {
    private static final String OPENSSL_FACTORY_CLASS_NAME = "com.oracle.jipher.internal.openssl.OpenSslFactory";

    public static OpenSsl getOpenSslSingleton() {

        // Trigger OpenSslFactory static initialisation
        // OpenSslFactory static initialisation must happen before the class is accessed via reflection
        new JipherJCE().getInfo();

        try {
            Class<?> cls = Class.forName(OPENSSL_FACTORY_CLASS_NAME);
            Method getInstance = cls.getDeclaredMethod("getInstance");
            getInstance.setAccessible(true);
            return (OpenSsl) getInstance.invoke(null);
        } catch (ReflectiveOperationException ex) {
            throw new Error(ex);
        }
    }
}
