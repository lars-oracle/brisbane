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

package com.oracle.jiphertest.helpers;

import java.security.Security;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.Set;
import java.util.TreeSet;
import java.util.regex.Pattern;

public class TlsConstraints {
    private static final Set<String>   TLS_DISABLED_ALGORITHMS;
    private static final List<Pattern> TLS_DISABLED_CIPHER_SUITE_PATTERNS;

    static
    {
        String property =  Security.getProperty("jdk.tls.disabledAlgorithms");

        String[] entries = null;
        if (property != null && !property.isEmpty()) {
            // remove double quote marks from beginning/end of the property
            if (property.length() >= 2 && property.charAt(0) == '"' &&
                    property.charAt(property.length() - 1) == '"') {
                property = property.substring(1, property.length() - 1);
            }
            entries = property.split(",");
            for (int i = 0; i < entries.length; i++) {
                entries[i] = entries[i].trim();
            }
        }

        Set<String> algorithms = new TreeSet<>(String.CASE_INSENSITIVE_ORDER);
        List<Pattern> patterns = new ArrayList<>();
        for (String entry : entries) {
            if (entry.contains("*")) {
                patterns.add(Pattern.compile("^\\Q" + entry.replace("*", "\\E.*\\Q") + "\\E$"));
            } else {
                algorithms.add(entry);
            }
        }

        TLS_DISABLED_ALGORITHMS = algorithms;
        TLS_DISABLED_CIPHER_SUITE_PATTERNS = Collections.unmodifiableList(patterns);
    }


    public static boolean permitted(String cipherSuite)
    {
        Set<String> algorithms = decomposeCipherSuite(cipherSuite);
        for (String algorithm : algorithms) {
            if (TLS_DISABLED_ALGORITHMS.stream().anyMatch(algorithm::equalsIgnoreCase)) {
                return false;
            }
        }
        if (TLS_DISABLED_CIPHER_SUITE_PATTERNS.stream().anyMatch(p -> p.matcher(cipherSuite).matches())) {
            return false;
        }
        return true;
    }

    public static Set<String> decomposeCipherSuite(String cipherSuite) {
        Set<String> algorithms = new TreeSet<>();

        String keyExchange = null;
        String authentication = null;
        String cipher;
        String hash;

        if (cipherSuite.contains("WITH")) {
            String[] component = cipherSuite.split("_");
            keyExchange = component[1];
            if ("RSA".equals(keyExchange)) {
                authentication = "RSA";
                cipher = component[3] + "_" + component[4] + "_" + component[5];
                hash = component[6];
            } else {
                authentication = component[2];
                cipher = component[4] + "_" + component[5] + "_" + component[6];
                hash = component[7];
            }
        } else {
            String[] component = cipherSuite.split("_");
            cipher = component[1] + "_" + component[2] + "_" + component[3];
            hash = component[4];
        }
        algorithms.add(cipher);

        if (keyExchange != null)  {
            algorithms.add(keyExchange);
            if ("DH".equals(keyExchange)) {
                algorithms.add("DiffieHellman");
            } else if ("DHE".equals(keyExchange)) {
                algorithms.add("DH");
                algorithms.add("DiffieHellman");
            }
            if (authentication != null) {
                algorithms.add(keyExchange + "_" + authentication);
            }
        }

        if (authentication != null) {
            algorithms.add(authentication);
            if ("DSS".equals(authentication)) {
                algorithms.add("DSA");
            }
        }

        if ("SHA".equals(hash)) {
            algorithms.add("SHA1");
            algorithms.add("SHA-1");
            algorithms.add("HmacSHA1");
        } else if ("SHA256".equals(hash)) {
            algorithms.add("SHA256");
            algorithms.add("SHA-256");
            algorithms.add("HmacSHA256");
        } else if ("SHA384".equals(hash)) {
            algorithms.add("SHA384");
            algorithms.add("SHA-384");
            algorithms.add("HmacSHA384");
        }

        return algorithms;
    }
}
