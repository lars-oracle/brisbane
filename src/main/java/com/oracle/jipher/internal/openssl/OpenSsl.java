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

import java.util.function.Consumer;

public interface OpenSsl {

    static OpenSsl getInstance() {
        return OpenSslFactory.getInstance();
    }

    /* The following are OpenSSL API constants defined in crypto.h */

    enum InitOption {
        NO_LOAD_CRYPTO_STRINGS, // 0x00000001L
        LOAD_CRYPTO_STRINGS,    // 0x00000002L
        ADD_ALL_CIPHERS,        // 0x00000004L
        ADD_ALL_DIGESTS,        // 0x00000008L
        NO_ADD_ALL_CIPHERS,     // 0x00000010L
        NO_ADD_ALL_DIGESTS,     // 0x00000020L
        LOAD_CONFIG,            // 0x00000040L
        NO_LOAD_CONFIG,         // 0x00000080L
        ASYNC,                  // 0x00000100L
        ENGINE_RDRAND,          // 0x00000200L
        ENGINE_DYNAMIC,         // 0x00000400L
        ENGINE_OPENSSL,         // 0x00000800L
        ENGINE_CRYPTODEV,       // 0x00001000L
        ENGINE_CAPI,            // 0x00002000L
        ENGINE_PADLOCK,         // 0x00004000L
        ENGINE_AFALG,           // 0x00008000L
        UNUSED1,                // 0x00010000L
        ATFORK,                 // 0x00020000L
        UNUSED2,                // 0x00040000L
        NO_ATEXIT               // 0x00080000L
    }

    enum VersionStringSelector {
        VERSION,              // 0
        CFLAGS,               // 1
        BUILT_ON,             // 2
        PLATFORM,             // 3
        DIR,                  // 4
        ENGINES_DIR,          // 5
        VERSION_STRING,       // 6
        FULL_VERSION_STRING,  // 7
        MODULES_DIR,          // 8
        CPU_INFO              // 9
    }

    enum InfoStringSelector {
        CONFIG_DIR,              // 1001
        ENGINES_DIR,             // 1002
        MODULES_DIR,             // 1003
        DSO_EXTENSION,           // 1004
        DIR_FILENAME_SEPARATOR,  // 1005
        LIST_SEPARATOR,          // 1006
        SEED_SOURCE,             // 1007
        CPU_SETTINGS             // 1008
    }

    // Methods used by tests
    void setNativeObjectLifecycleCallback(NativeObjectLifecycleCallback lifecycleCallback);
    void clearNativeObjectLifecycleCallback();
    void clearObjectPools();

    void initCrypto(InitOption... opts);
    int versionMajor();
    int versionMinor();
    int versionPatch();
    String versionString(VersionStringSelector selector);
    String infoString(InfoStringSelector selector);
    String versionBuildMetadataString();
    int getError();
    int peekError();
    int peekLastError();
    void forEachError(Consumer<String> consumer);
    void clearErrorQueue();

    OSSL_LIB_CTX getDefaultOsslLibCtx();

    OsslArena arenaGlobal();
    OsslArena arenaOfAuto();
    OsslArena arenaOfConfined();

    OsslParamBuffer emptyParamBuffer();
    OsslParamBuffer templateParamBuffer(OSSL_PARAM... params);
    OsslParamBuffer templateParamBuffer(OsslArena osslArena, OSSL_PARAM... params);
    OsslParamBuffer dataParamBuffer(OSSL_PARAM... params);
    OsslParamBuffer dataParamBuffer(OsslArena osslArena, OSSL_PARAM... params);

    OSSL_LIB_CTX newOsslLibCtx(OsslArena arena);
    default OSSL_LIB_CTX newOsslLibCtx() {
        return newOsslLibCtx(OsslArena.ofAuto());
    }

    EVP_CIPHER_CTX newEvpCipherCtx(OsslArena arena);
    EVP_CIPHER_CTX newEvpCipherCtx();

    EVP_KDF_CTX newEvpKdfCtx(EVP_KDF type, OsslArena arena);
    default EVP_KDF_CTX newEvpKdfCtx(EVP_KDF type) {
        return newEvpKdfCtx(type, OsslArena.ofAuto());
    }

    EVP_MAC_CTX newEvpMacCtx(EVP_MAC type, OsslArena arena);
    EVP_MAC_CTX newEvpMacCtx(EVP_MAC type);

    EVP_MD_CTX newEvpMdCtx(OsslArena arena);
    EVP_MD_CTX newEvpMdCtx();

    EVP_RAND_CTX newEvpRandCtx(EVP_RAND type, EVP_RAND_CTX parent, OsslArena arena);
    default EVP_RAND_CTX newEvpRandCtx(EVP_RAND type, EVP_RAND_CTX parent) {
        return newEvpRandCtx(type, parent, OsslArena.ofAuto());
    }

    EVP_PKEY newEvpPkey(OsslArena osslArena);
    default EVP_PKEY newEvpPkey() {
        return newEvpPkey(OsslArena.ofAuto());
    }
}
