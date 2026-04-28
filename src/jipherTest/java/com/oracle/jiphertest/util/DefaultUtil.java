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

package com.oracle.jiphertest.util;

import java.util.Arrays;
import java.util.HashMap;
import java.util.Map;

public class DefaultUtil {

    static Map<String, int[]> algorithmSupportedKeySizes = new HashMap<>();

    static {
        algorithmSupportedKeySizes.put("AES", new int[]{128, 192, 256});
        algorithmSupportedKeySizes.put("DH",  new int[]{3072, 2048, 4096});
        algorithmSupportedKeySizes.put("DSA", new int[]{2048, 3072});
        algorithmSupportedKeySizes.put("EC",  new int[]{256, 384, 521});
        algorithmSupportedKeySizes.put("RSA", new int[]{3072, 2048, 4096});
    }

    //  Gets the expected default key size for the specified algorithm name
    //  by processing the security property 'jdk.security.defaultKeySize'
    //  If the security property 'jdk.security.defaultKeySize' is not set or
    //  if the specified algorithm name is not listed in the security property's value or
    //  if the specified algorithm name key size is not supported then
    //  the expected JipherJCE provider default key size is returned.
    //
    // NB: This utility does not check the 'jdk.security.defaultKeySize' security property for invalid syntax
    //
    public static int getExpectedKeySize(String algorithmName) {
        int[] supportedKeySizes = algorithmSupportedKeySizes.get(algorithmName.toUpperCase());
        int defaultKeySize = supportedKeySizes[0];

        String defaultKeySizePropertyValue = System.getProperty("jdk.security.defaultKeySize");
        if (defaultKeySizePropertyValue != null) {
            String[] pairs = defaultKeySizePropertyValue.split(",");
            for (String pair : pairs) {
                String[] algoAndValue = pair.split(":");
                if (algoAndValue.length == 2) {
                    if (algorithmName.equalsIgnoreCase(algoAndValue[0].trim())) {
                        int value = Integer.parseInt(algoAndValue[1].trim());
                        if (Arrays.stream(supportedKeySizes).anyMatch(x -> x == value)) {
                            defaultKeySize = value;
                        }
                    }
                }
            }
        }
        return defaultKeySize;
    }
}
