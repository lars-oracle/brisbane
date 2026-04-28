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

import java.lang.reflect.Constructor;
import java.security.spec.AlgorithmParameterSpec;
import javax.crypto.SecretKey;

public class TlsUtil {

    public static AlgorithmParameterSpec newTlsKeyMaterialParameterSpec(
            SecretKey masterSecret, int majVer, int minVer, byte[] clientRandom, byte[] serverRandom, String cipherAlg,
            int ciphKeyLen, int expandedCiphKeyLen, int ivLen, int macKeyLen, String prfHashAlg, int prfHashLen,
            int prfBlockSize, String cipherSuiteName) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsKeyMaterialParameterSpec");
            Constructor con = specClass.getConstructor(SecretKey.class, int.class, int.class, byte[].class, byte[].class, String.class, int.class, int.class, int.class, int.class, String.class, int.class, int.class);
            return (AlgorithmParameterSpec) con.newInstance(masterSecret, majVer, minVer, clientRandom, serverRandom, cipherAlg, ciphKeyLen, expandedCiphKeyLen, ivLen, macKeyLen, prfHashAlg, prfHashLen, prfBlockSize);
        } catch (Exception e) {
            throw new Error(e);
        }

    }

    public static AlgorithmParameterSpec newTlsMasterSecretParameterSpec(
            SecretKey premasterSecret, int majorVersion, int minorVersion, byte[] clientRandom, byte[] serverRandom,
            String prfHashAlg, int prfHashLength, int prfBlockSize) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsMasterSecretParameterSpec");
            Constructor con = specClass.getConstructor(SecretKey.class, int.class, int.class, byte[].class, byte[].class, String.class, int.class, int.class);
            return (AlgorithmParameterSpec) con.newInstance(premasterSecret, majorVersion, minorVersion, clientRandom, serverRandom, prfHashAlg, prfHashLength, prfBlockSize);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static AlgorithmParameterSpec newTlsMasterSecretParameterSpec(
            SecretKey premasterSecret, int majorVersion, int minorVersion, byte[] extendedMasterSecretSessionHash,
            String prfHashAlg, int prfHashLength, int prfBlockSize) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsMasterSecretParameterSpec");
            Constructor con = specClass.getConstructor(SecretKey.class, int.class, int.class, byte[].class, String.class, int.class, int.class);
            return (AlgorithmParameterSpec) con.newInstance(premasterSecret, majorVersion, minorVersion,
                        extendedMasterSecretSessionHash, prfHashAlg, prfHashLength, prfBlockSize);
        } catch (Exception e) {
            throw new Error(e);
        }
    }


    public static AlgorithmParameterSpec newTlsPrfParameterSpec(SecretKey secret, String label,
                                                                byte[] seed, int outputLength,
                                                                String prfHashAlg, int prfHashLength, int prfBlockSize) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsPrfParameterSpec");
            Constructor con = specClass.getConstructor(SecretKey.class, String.class, byte[].class, int.class, String.class, int.class, int.class);
            return (AlgorithmParameterSpec) con.newInstance(secret, label, seed, outputLength, prfHashAlg, prfHashLength, prfBlockSize);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static AlgorithmParameterSpec newTlsRsaPremasterSecretParameterSpec(int var1, int var2) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec");
            Constructor con = specClass.getConstructor(int.class, int.class);
            return (AlgorithmParameterSpec) con.newInstance(var1, var2);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static AlgorithmParameterSpec newTlsRsaPremasterSecretParameterSpec(int var1, int var2, byte[] encodedSecret) {
        try {
            Class<?> specClass = Class.forName("sun.security.internal.spec.TlsRsaPremasterSecretParameterSpec");
            Constructor con = specClass.getConstructor(int.class, int.class, byte[].class);
            return (AlgorithmParameterSpec) con.newInstance(var1, var2, encodedSecret);
        } catch (Exception e) {
            throw new Error(e);
        }
    }

    public static Class<?> getTlsMasterSecretClass() {
        try {
            return Class.forName("sun.security.internal.interfaces.TlsMasterSecret");
        } catch (Exception e) {
            throw new Error(e);
        }
    }
}
