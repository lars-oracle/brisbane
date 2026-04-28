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

package com.oracle.jipher.internal.openssl;

import java.security.ProviderException;
import java.text.ParseException;

import com.oracle.jipher.internal.openssl.ffm.OpenSslLoader;
import com.oracle.jipher.internal.platform.OsslLocator;

public class OpenSslFactory {

    /**
     * The OpenSsl singleton instance.
     */
    private static final OpenSsl OPENSSL_INSTANCE;
    private static final Exception INIT_EXCEPTION;

    static {
        OpenSsl instance;
        Exception exception = null;
        try {
            instance = load();
            checkSanctionedVersion(instance);
        } catch (Exception e) {
            instance = null;
            exception = e;
        }
        OPENSSL_INSTANCE = instance;
        INIT_EXCEPTION = exception;
    }

    private static OpenSsl load() {

        // Setting the java.testing.lifecycleHooks.enable System property to true prior to Jipher being
        // initialized enables the lifecycle hooks, which will deliver NEW/UP_REF/FREE events to
        // a com.oracle.jipher.internal.openssl.NativeObjectLifecycleCallback that can be installed by
        // calling the
        //     void setNativeObjectLifecycleCallback(NativeObjectLifecycleCallback lifecycleCallback);
        // method on the com.oracle.jipher.internal.openssl.OpenSsl instance.
        //
        // Each event includes the operation type (NEW/UP_REF/FREE), the name of the OpenSSL function
        // and the pointer to the native object.  These events can be used for leak testing.
        //
        // The lifecycle hooks are implemented by instrumenting downcall MethodHandles for all OpenSSL
        // functions that are involved with OpenSSL object creation, up-ref-ing and freeing, including
        // the case where the pointer to the new object is returned via an out parameter.  There is no
        // performance overhead when the hooks have not been enabled.
        boolean enableLifecycleHooks = Boolean.getBoolean("java.testing.lifecycleHooks.enable");

        return OpenSslLoader.load(OsslLocator.getCryptoLibPath(), enableLifecycleHooks);
    }

    private static void checkSanctionedVersion(OpenSsl instance) throws ParseException {
        String versionString;
        try {
            versionString = instance.versionString(OpenSsl.VersionStringSelector.VERSION_STRING);
        } catch (Exception e) {
            versionString = null;
        }
        if (!VersionSanctioner.CryptoLibrary.accept(versionString)) {
            throw new ProviderException(String.format(
                    "OpenSSL cryptography library version '%s' is not a sanctioned version '%s'",
                    versionString, VersionSanctioner.CryptoLibrary.getSanctionedVersions()));
        }
    }

    /**
     * Factory method for returning the OpenSsl instance.
     * @return the OpenSsl instance
     */
    static OpenSsl getInstance() {
        if (OPENSSL_INSTANCE != null) {
            return OPENSSL_INSTANCE;
        }
        throw new ProviderException("Failed to load OpenSSL", INIT_EXCEPTION);
    }
}
