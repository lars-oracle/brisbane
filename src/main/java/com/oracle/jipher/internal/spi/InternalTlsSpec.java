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

import java.lang.reflect.InvocationHandler;
import java.lang.reflect.InvocationTargetException;
import java.lang.reflect.Method;
import java.lang.reflect.Proxy;
import java.security.InvalidAlgorithmParameterException;
import java.security.ProviderException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.Arrays;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

/**
 * Abstract parent class for internal wrapper classes for JDK-internal TLS-related spec classes.
 */
abstract class InternalTlsSpec implements AlgorithmParameterSpec {
    private final AlgorithmParameterSpec spec;
    private final Class<?> specClass;

    InternalTlsSpec(Class specClass, AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
        if (!specClass.isInstance(spec)) {
            throw new InvalidAlgorithmParameterException("Expected " + specClass.getName());
        }
        this.specClass = specClass;
        this.spec = spec;
    }

    Object call(String methodName) {
        try {
            return specClass.getMethod(methodName).invoke(this.spec);
        } catch (NoSuchMethodException | InvocationTargetException | IllegalAccessException e) {
            throw new ProviderException("Problem loading JDK-internal parameter spec classes", e);
        }
    }

    static Class getTlsSpecClass(String className) {
        try {
            return Class.forName("sun.security.internal.spec." + className);
        } catch (ClassNotFoundException e) {
            throw new ProviderException("Problem loading JDK-internal parameter spec classes");
        }
    }

    /**
     * Internal wrapper class for TlsKeyMaterialParameterSpec
     */
    static class KeyMaterialParamSpec extends InternalTlsSpec {

        private static final Class SPEC_CLASS = getTlsSpecClass("TlsKeyMaterialParameterSpec");

        KeyMaterialParamSpec(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            super(SPEC_CLASS, spec);
        }

        SecretKey getMasterSecret() {
            return (SecretKey) call("getMasterSecret");
        }

        int getMajorVersion() {
            return (int) call("getMajorVersion");
        }

        int getMinorVersion() {
            return (int) call("getMinorVersion");
        }

        byte[] getClientRandom() {
            return (byte[]) call("getClientRandom");
        }

        byte[] getServerRandom() {
            return (byte[]) call("getServerRandom");
        }

        String getCipherAlgorithm() {
            return (String) call("getCipherAlgorithm");
        }

        int getCipherKeyLength() {
            return (int) call("getCipherKeyLength");
        }

        int getIvLength() {
            return (int) call("getIvLength");
        }

        int getMacKeyLength() {
            return (int) call("getMacKeyLength");
        }

        String getPRFHashAlg() {
            return (String) call("getPRFHashAlg");
        }

    }

    /**
     * Internal wrapper class for TlsMasterSecretParameterSpec
     */
    static class MasterSecretParameterSpec extends InternalTlsSpec {

        private static final Class SPEC_CLASS = getTlsSpecClass("TlsMasterSecretParameterSpec");

        MasterSecretParameterSpec(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            super(SPEC_CLASS, spec);
        }

        SecretKey getPremasterSecret() {
            return (SecretKey) call("getPremasterSecret");
        }

        int getMajorVersion() {
            return (int) call("getMajorVersion");
        }

        int getMinorVersion() {
            return (int) call("getMinorVersion");
        }

        byte[] getClientRandom() {
            return (byte[]) call("getClientRandom");
        }

        byte[] getServerRandom() {
            return (byte[]) call("getServerRandom");
        }

        byte[] getExtendedMasterSecretSessionHash() {
            return (byte[]) call("getExtendedMasterSecretSessionHash");
        }

        String getPRFHashAlg() {
            return (String) call("getPRFHashAlg");
        }

    }

    /**
     * Internal wrapper class for TlsPrfParameterSpec
     */
    static class PrfParameterSpec extends InternalTlsSpec {

        private static final Class SPEC_CLASS = getTlsSpecClass("TlsPrfParameterSpec");

        PrfParameterSpec(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            super(SPEC_CLASS, spec);
        }

        SecretKey getSecret() {
            return (SecretKey) call("getSecret");
        }

        String getLabel() {
            return (String) call("getLabel");
        }

        byte[] getSeed() {
            return (byte[]) call("getSeed");
        }

        int getOutputLength() {
            return (int) call("getOutputLength");
        }

        String getPRFHashAlg() {
            return (String) call("getPRFHashAlg");
        }
    }

    /**
     * Internal wrapper class for TlsRsaPremasterSecretParameterSpec
     */
    static class RsaPremasterSecretParamSpec extends InternalTlsSpec {
        private static final Class SPEC_CLASS = getTlsSpecClass("TlsRsaPremasterSecretParameterSpec");

        RsaPremasterSecretParamSpec(AlgorithmParameterSpec spec) throws InvalidAlgorithmParameterException {
            super(SPEC_CLASS, spec);
        }

        int getMajorVersion() {
            return (int) call("getMajorVersion");
        }

        int getMinorVersion() {
            return (int) call("getMinorVersion");
        }

        byte[] getEncodedSecret() {
            return (byte[]) call("getEncodedSecret");
        }

        static boolean isInstance(AlgorithmParameterSpec spec) {
            return SPEC_CLASS.isInstance(spec);
        }

    }

    /**
     * Returns a {@link SecretKey} object that implements the JDK-specific {@code TlsMasterSecret} interface.
     * @param key the key bytes
     * @param maj the major version
     * @param min the minor version
     * @return a Proxy instance which implements TlsMasterSecret for the running JDK
     */
    static SecretKey newTlsMasterSecretKey(byte[] key, final int maj, final int min) {
        try {
            Class cls = Class.forName("sun.security.internal.interfaces.TlsMasterSecret");
            Object tlsMasterKey = Proxy.newProxyInstance(InternalTlsSpec.class.getClassLoader(),
                    new Class[]{cls},
                    new TlsMasterSecretHandler(maj, min, key));
            return (SecretKey) tlsMasterKey;
        } catch (ClassNotFoundException e) {
            return new SecretKeySpec(key, "TlsMasterSecret");
        }
    }

    static class TlsMasterSecretHandler implements InvocationHandler {

        private final int major;
        private final int minor;
        private byte[] key;
        private TlsMasterSecretHandler(int major, int minor, byte[] key) {
            this.major = major;
            this.minor = minor;
            this.key = key;
        }

        public Object invoke(Object proxy, Method method, Object[] args) {
            return switch (method.getName()) {
                case "getMajorVersion" -> this.major;
                case "getMinorVersion" -> this.minor;
                case "getEncoded" -> {
                    if (this.key == null) {
                        throw new IllegalStateException("key data has been cleared");
                    }
                    yield this.key.clone();
                }
                case "getFormat" -> "RAW";
                case "getAlgorithm" -> "TlsMasterSecret";
                case "destroy" -> {
                    if (this.key != null) {
                        Arrays.fill(this.key, (byte) 0);
                        this.key = null;
                    }
                    yield null;
                }
                case "isDestroyed" -> this.key == null;
                default -> null;
            };
        }

    }
}
