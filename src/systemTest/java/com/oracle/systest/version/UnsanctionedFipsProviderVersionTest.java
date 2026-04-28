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

package com.oracle.systest.version;

import java.security.ProviderException;

import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Assumptions;
import org.junit.jupiter.api.BeforeAll;
import org.junit.jupiter.api.Test;

import com.oracle.jipher.provider.JipherJCE;

public class UnsanctionedFipsProviderVersionTest {

    @BeforeAll
    static void checkSanctionedFipsProviderVersionsSystemPropertySettings() {
        // This system test assumes Jipher has been configured with an empty Fips Provider version range.
        final String expectedPropertyValue = "(1.2.3, 1.2.3)";
        for (String prefix : new String[]{"jipher.openssl.sanctioned.", "jipher.openssl.sanctioned.osProvided."}) {
            String propertyName = prefix + "fipsProviderVersions";
            Assumptions.assumeTrue(System.getProperty(propertyName, "").equals(expectedPropertyValue));
        }
    }

    @Test
    public void isAvailable()  {
        Assertions.assertFalse(JipherJCE.isAvailable());
    }

    @Test
    public void loadingException()  {
        Throwable t = JipherJCE.loadingException();
        validateCause(t);
    }

    @Test
    public void loadJipher()  {
        try {
            new JipherJCE();
            Assertions.fail("Should throw ProviderException");
        } catch (ProviderException e) {
            validateCause(e);
        }
    }

    private void validateCause(Throwable t) {
        Assertions.assertNotNull(t);
        while (t.getCause() != null && t.getCause() != t) {
            t = t.getCause();
        }
        Assertions.assertInstanceOf(ProviderException.class, t);
        String message = t.getMessage();
        Assertions.assertTrue(message.contains("OpenSSL FIPS provider version"));
        Assertions.assertTrue(message.contains("is not a sanctioned version"));
    }
}
