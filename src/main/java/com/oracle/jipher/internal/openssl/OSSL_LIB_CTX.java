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

import java.util.Optional;
import java.util.function.Consumer;
import java.util.function.Function;
import java.util.function.Predicate;

public interface OSSL_LIB_CTX {

    static OSSL_LIB_CTX getDefaultInstance() {
        return OpenSsl.getInstance().getDefaultOsslLibCtx();
    }

    void setDefaultProviderSearchPath(String modulesPath);
    void loadConfig(String configFile);
    boolean isProviderAvailable(String providerName);
    <T> Optional<T> forProvider(String providerName, Function<OSSL_PROVIDER,? extends T> mapper);
    boolean forEachProvider(Predicate<OSSL_PROVIDER> callback);
    void setDefaultProperties(String propq);
    void enableFips(boolean enable);
    boolean isFipsEnabled();
    void randBytes(byte[] bytes, int strength);
    void randPrivBytes(byte[] bytes, int strength);

    default EVP_RAND_CTX newEvpRandCtxWithPrimaryAsParent(EVP_RAND type) {
        return newEvpRandCtxWithPrimaryAsParent(type, OsslArena.ofAuto());
    }
    EVP_RAND_CTX newEvpRandCtxWithPrimaryAsParent(EVP_RAND type, OsslArena arena);

    void setConfig(String config);

    void forEachCipher(Consumer<EVP_CIPHER> consumer);
    default EVP_CIPHER fetchCipher(String algorithm, String properties) {
        return fetchCipher(algorithm, properties, OsslArena.ofAuto());
    }
    EVP_CIPHER fetchCipher(String algorithm, String properties, OsslArena arena);

    void forEachKdf(Consumer<EVP_KDF> consumer);
    default EVP_KDF fetchKdf(String algorithm, String properties) {
        return fetchKdf(algorithm, properties, OsslArena.ofAuto());
    }
    EVP_KDF fetchKdf(String algorithm, String properties, OsslArena arena);

    void forEachMac(Consumer<EVP_MAC> consumer);
    default EVP_MAC fetchMac(String algorithm, String properties) {
        return fetchMac(algorithm, properties, OsslArena.ofAuto());
    }
    EVP_MAC fetchMac(String algorithm, String properties, OsslArena arena);

    void forEachMd(Consumer<EVP_MD> consumer);
    default EVP_MD fetchMd(String algorithm, String properties) {
        return fetchMd(algorithm, properties, OsslArena.ofAuto());
    }
    EVP_MD fetchMd(String algorithm, String properties, OsslArena arena);

    void forEachRand(Consumer<EVP_RAND> consumer);
    default EVP_RAND fetchRand(String algorithm, String properties) {
        return fetchRand(algorithm, properties, OsslArena.ofAuto());
    }
    EVP_RAND fetchRand(String algorithm, String properties, OsslArena arena);

    default EVP_PKEY_CTX newPkeyCtx(String name, String properties) {
        return newPkeyCtx(name, properties, OsslArena.ofAuto());
    }
    EVP_PKEY_CTX newPkeyCtx(String name, String properties, OsslArena osslArena);
    default EVP_PKEY_CTX newPkeyCtx(EVP_PKEY pkey, String properties) {
        return newPkeyCtx(pkey, properties, OsslArena.ofAuto());
    }
    EVP_PKEY_CTX newPkeyCtx(EVP_PKEY pkey, String properties, OsslArena osslArena);
}
