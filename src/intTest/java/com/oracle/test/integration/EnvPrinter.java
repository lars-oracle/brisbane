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

package com.oracle.test.integration;

import java.security.Provider;
import java.security.SecureRandom;
import java.security.Security;

import org.junit.Test;

/**
 * This test class is intended to print out some environment information that
 * may be useful for verifying the environment of this test suite execution.
 */
public class EnvPrinter {

    @Test
    public void printEnv() throws Exception {
        String[] secProps = new String[]{"securerandom.source","policy.expandProperties","policy.allowSystemProperty"};
        StringBuilder sb = new StringBuilder();
        sb.append("Security Properties: \n");
        for (String s : secProps) {
            sb.append("  ").append(s).append("=").append(Security.getProperty(s)).append("\n");
        }
        Provider[] provs = Security.getProviders();
        for (int i = 0; i < provs.length; i++) {
            sb.append("  security.provider.").append(i+1).append("=").append(provs[i].getClass().getName()).append("\n");
        }
        sb.append("Default SecureRandom.provider: ").append(new SecureRandom().getProvider().getName()).append("\n");

        String[] props = new String[]{"java.security.properties",
                "jdk.module.path",
                "java.class.path",
                "java.runtime.name",
                "java.runtime.version",
                "java.specification.version",
                "java.security.debug",
                "java.version",
                "java.vendor",
                "java.home",
                "java.io.tmpdir",
                "os.arch",
                "os.name"
        };
        sb.append("System properties: \n");
        for (String p : props) {
            String[] parts = System.getProperty(p, "").split(":");
            sb.append("  ").append(p).append("=");
            for (String s : parts) {
                sb.append("      ").append(s).append("\n");
            }
        }
        System.out.println(sb.toString());
    }
}
