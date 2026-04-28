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

package com.oracle.jipher.internal.spi;

import java.security.NoSuchAlgorithmException;
import java.util.HashMap;
import java.util.LinkedList;
import java.util.List;
import java.util.Map;
import java.util.Objects;
import java.util.concurrent.atomic.AtomicReference;
import java.util.function.Function;
import javax.crypto.Cipher;

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.common.ToolkitProperties;

/**
 * Utility class for accessing default key sizes for specific cryptographic algorithms.
 *
 * <p>These default key sizes are used by Jipher's {@link java.security.KeyPairGenerator}
 * implementations when the application does not specify a specific key size to generate.
 *
 * <p>This class respects the {@systemProperty jdk.security.defaultKeySize} system property
 * when determining the default key sizes for specific cryptographic algorithms.
 * If a default key size for a specific cryptographic algorithm is not specified in the
 * {@systemProperty jdk.security.defaultKeySize} system property then the default
 * key size will be set according CSNA 2.0.
 * The one exception is EC which defaults to P-256.
 */
public class KeySizeConfiguration {

    private static final Debug DEBUG = Debug.getInstance("jipher");

    private static final Function<Integer, Boolean> AES_FILTER = t -> {
        try {
            return Cipher.getMaxAllowedKeyLength("AES") >= t;
        } catch (NoSuchAlgorithmException e) {
            return true;
        }
    };

    // Enum to bind algo names with permitted key sizes.
    private enum CryptoAlgo {

        // Defaults values, the first entries in the lists below, are set according to CSNA 2.0.
        // The one exception is EC, where CSNA recommends P-384 but Jipher uses P-256 by default.
        // It does this because the OpenSSL FIPS provider has an optimised P-256 implementation
        // but only has an optimised P-384 implementation on 64-bit intel architectures.
        RSA(3072, 2048, 4096),
        EC(256, 384, 521),
        AES(AES_FILTER, 256, 192, 128),
        DH(3072, 2048, 4096);

        private final int defaultValue;

        private final List<Integer> permittedValues;

        CryptoAlgo(int... sizeValues) {
            this.defaultValue = sizeValues[0];
            permittedValues = new LinkedList<>();
            for (int val : sizeValues) {
                permittedValues.add(val);
            }
        }

        CryptoAlgo(Function<Integer, Boolean> valFilter, int... sizeValues) {
            // Default Value is the first that passes the filter test.
            permittedValues = new LinkedList<>();
            for (int val : sizeValues) {
                boolean isValid = valFilter.apply(val);
                if (isValid) {
                    permittedValues.add(val);
                }
            }
            // At least one value from sizeValues needs to pass the filter.
            defaultValue = permittedValues.get(0);
        }

        int getSize() {
            return defaultValue;
        }

        boolean isPermitted(int value) {
            return permittedValues.contains(value);
        }
    }

    // Holds a snapshot of a key size configurations based on a specific instance of propValue.
    private static class ImmutableKeySizeHolder {
        private final String propValue;
        private final int rsaSize;
        private final int ecSize;
        private final int aesSize;
        private final int dhSize;

        public static final ImmutableKeySizeHolder DEF_INSTANCE = new ImmutableKeySizeHolder(null,
                CryptoAlgo.RSA.getSize(), CryptoAlgo.EC.getSize(), CryptoAlgo.AES.getSize(),
                CryptoAlgo.DH.getSize());


        private ImmutableKeySizeHolder(String propValue, int rsaSize, int ecSize, int aesSize,
                int dhSize) {
            this.propValue = propValue;
            this.rsaSize = rsaSize;
            this.ecSize = ecSize;
            this.aesSize = aesSize;
            this.dhSize = dhSize;
        }

        public ImmutableKeySizeHolder getInstance(String inPropValue) {
            // return current values if prop has not changed.
            if (Objects.equals(this.propValue, inPropValue)) {
                return this;
            }

            DEBUG.println("Property value change detected, updating default key sizes");
            Map<CryptoAlgo, Integer> sizeMap = parse(inPropValue);
            return new ImmutableKeySizeHolder(inPropValue,
                    sizeMap.getOrDefault(CryptoAlgo.RSA, CryptoAlgo.RSA.getSize()),
                    sizeMap.getOrDefault(CryptoAlgo.EC, CryptoAlgo.EC.getSize()),
                    sizeMap.getOrDefault(CryptoAlgo.AES, CryptoAlgo.AES.getSize()),
                    sizeMap.getOrDefault(CryptoAlgo.DH, CryptoAlgo.DH.getSize()));
        }

        // Logic as per sun.security.util.SecurityProviderConstants without explicit dependency on
        // an internal API.
        private Map<CryptoAlgo, Integer> parse(String propValue) {

            Map<CryptoAlgo, Integer> sizeMap = new HashMap<>();

            if (propValue != null) {
                // format expected algo1:keysize2,algo2:keysize2 ....
                String[] pairs = propValue.split(",");
                for (String p : pairs) {
                    String[] algoAndValue = p.split(":");
                    if (algoAndValue.length != 2) {
                        // invalid pair, skip to next pair
                        if (DEBUG != null) {
                            DEBUG.println("Ignoring invalid pair in " + p);
                        }
                        continue;
                    }
                    String algoName = algoAndValue[0].trim().toUpperCase();
                    int value;
                    try {
                        value = Integer.parseInt(algoAndValue[1].trim());
                    } catch (NumberFormatException nfe) {
                        // invalid value, skip to next pair
                        if (DEBUG != null) {
                            DEBUG.println("Ignoring invalid value in " + p);
                        }
                        continue;
                    }

                    try {
                        CryptoAlgo algo = CryptoAlgo.valueOf(algoName);
                        if (algo.isPermitted(value)) {
                            sizeMap.put(algo, value);
                        }
                    } catch (IllegalArgumentException e) {
                        DEBUG.println("Ignoring unsupported algo in " + p);
                    }
                }
            }

            return sizeMap;
        }
    }

    private static final AtomicReference<ImmutableKeySizeHolder> KEY_SIZES =
            new AtomicReference<>(ImmutableKeySizeHolder.DEF_INSTANCE);

    /*
     * update the map as per the system prop value
     */
    private static void update() {
        String propValue = ToolkitProperties.getJavaKeyLengths();
        KEY_SIZES.set(KEY_SIZES.get().getInstance(propValue));
    }

    /**
     * Gets the configured (or default if not configured) RSA Key Size in bits
     *
     * @return the configured (or default if not configured) RSA Key Size in bits
     */
    public static int getRSAKeySize() {
        update();
        return KEY_SIZES.get().rsaSize;
    }

    /**
     * Gets the configured (or default if not configured) EC Key Size in bits
     *
     * @return the configured (or default if not configured) EC Key Size in bits
     */
    public static int getECKeySize() {
        update();
        return KEY_SIZES.get().ecSize;
    }

    /**
     * Gets the configured (or default if not configured) AES Key Size in bits
     *
     * @return the configured (or default if not configured) AES Key Size in bits
     */
    public static int getAESKeySize() {
        update();
        return KEY_SIZES.get().aesSize;
    }

    /**
     * Gets the configured (or default if not configured) DH Key Size in bits
     *
     * @return the configured (or default if not configured) DH Key Size in bits
     */
    public static int getDHKeySize() {
        update();
        return KEY_SIZES.get().dhSize;
    }
}
