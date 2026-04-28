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

package com.oracle.jipher.internal.openssl.ffm;

import java.lang.foreign.Arena;
import java.lang.foreign.MemorySegment;
import java.lang.invoke.MethodHandle;
import java.util.function.Consumer;

import com.oracle.jipher.internal.openssl.EVP_CIPHER;
import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DO_ALL_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.GET0_STRING_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.INT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.IS_A_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LONG_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NAME_CALLBACK_UPCALL_STUB;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PTR_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.UP_REF_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.callNameCallback;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;

final class EvpCipher implements EVP_CIPHER {

    static final MethodHandle EVP_CIPHER_UP_REF_FUNC;
    static final MethodHandle EVP_CIPHER_IS_A_FUNC;
    static final MethodHandle EVP_CIPHER_NAMES_DO_ALL_FUNC;
    static final MethodHandle EVP_CIPHER_GET0_NAME_FUNC;
    static final MethodHandle EVP_CIPHER_GET0_DESCRIPTION_FUNC;
    static final MethodHandle EVP_CIPHER_GET0_PROVIDER_FUNC;
    static final MethodHandle EVP_CIPHER_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_GETTABLE_CTX_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_SETTABLE_CTX_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_GET_PARAMS_FUNC;
    static final MethodHandle EVP_CIPHER_GET_BLOCK_SIZE_FUNC;
    static final MethodHandle EVP_CIPHER_GET_KEY_LENGTH_FUNC;
    static final MethodHandle EVP_CIPHER_GET_IV_LENGTH_FUNC;
    static final MethodHandle EVP_CIPHER_GET_FLAGS_FUNC;
    static final MethodHandle EVP_CIPHER_GET_MODE_FUNC;
    static final MethodHandle EVP_CIPHER_FREE_FUNC;

    static {
        EVP_CIPHER_UP_REF_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_up_ref", UP_REF_FUNCDESC);
        EVP_CIPHER_IS_A_FUNC = downcallHandle(
                "EVP_CIPHER_is_a", IS_A_FUNCDESC);
        EVP_CIPHER_NAMES_DO_ALL_FUNC = downcallHandle(
                "EVP_CIPHER_names_do_all", DO_ALL_FUNCDESC);
        EVP_CIPHER_GET0_NAME_FUNC = downcallHandle(
                "EVP_CIPHER_get0_name", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET0_DESCRIPTION_FUNC = downcallHandle(
                "EVP_CIPHER_get0_description", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET0_PROVIDER_FUNC = downcallHandleCheckNull(
                "EVP_CIPHER_get0_provider", PTR_FUNCDESC, CRITICAL);
        EVP_CIPHER_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_CIPHER_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_CIPHER_GETTABLE_CTX_PARAMS_FUNC = downcallHandle(
                "EVP_CIPHER_gettable_ctx_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_CIPHER_SETTABLE_CTX_PARAMS_FUNC = downcallHandle(
                "EVP_CIPHER_settable_ctx_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_CIPHER_get_params", PARAMS_FUNCDESC);
        EVP_CIPHER_GET_BLOCK_SIZE_FUNC = downcallHandle(
                "EVP_CIPHER_get_block_size", INT_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET_KEY_LENGTH_FUNC = downcallHandle(
                "EVP_CIPHER_get_key_length", INT_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET_IV_LENGTH_FUNC = downcallHandle(
                "EVP_CIPHER_get_iv_length", INT_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET_FLAGS_FUNC = downcallHandle(
                "EVP_CIPHER_get_flags", LONG_FUNCDESC, CRITICAL);
        EVP_CIPHER_GET_MODE_FUNC = downcallHandle(
                "EVP_CIPHER_get_mode", LONG_FUNCDESC, CRITICAL);
        EVP_CIPHER_FREE_FUNC = downcallHandle(
                "EVP_CIPHER_free", FREE_FUNCDESC);
    }

    final MemorySegment evpCipher;
    final int blockSize;
    final int keyLength;
    final int ivLength;
    final long flags;
    final Mode mode;

    EvpCipher(MemorySegment evpCipher, Arena arena) {
        this(evpCipher, arena, EvpCipher::free);
    }

    EvpCipher(MemorySegment evpCipher, Arena arena, Consumer<MemorySegment> cleanup) {
        this.evpCipher = evpCipher.reinterpret(arena, cleanup);
        try {
            this.blockSize = (int) EVP_CIPHER_GET_BLOCK_SIZE_FUNC.invokeExact(this.evpCipher);
            this.keyLength = (int) EVP_CIPHER_GET_KEY_LENGTH_FUNC.invokeExact(this.evpCipher);
            this.ivLength = (int) EVP_CIPHER_GET_IV_LENGTH_FUNC.invokeExact(this.evpCipher);
            this.flags = (long) EVP_CIPHER_GET_FLAGS_FUNC.invokeExact(this.evpCipher);
            this.mode = Mode.lookup((long) EVP_CIPHER_GET_MODE_FUNC.invokeExact(this.evpCipher));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    EvpCipher(MemorySegment evpCipher, int blockSize, int keyLength, int ivLength, long flags, Mode mode, Arena arena) {
        this.evpCipher = evpCipher.reinterpret(arena, EvpCipher::free);
        this.blockSize = blockSize;
        this.keyLength = keyLength;
        this.ivLength = ivLength;
        this.flags = flags;
        this.mode = mode;
    }

    static void free(MemorySegment seg) {
        try {
            EVP_CIPHER_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_CIPHER upRef(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpCipherPtr = MemorySegment.ofAddress(this.evpCipher.address());
        try {
            EVP_CIPHER_UP_REF_FUNC.invokeExact(this.evpCipher);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpCipher(evpCipherPtr, this.blockSize, this.keyLength, this.ivLength, this.flags, this.mode, arena);
    }

    @Override
    public boolean isA(String name) {
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment nameStr = confinedArena.allocateFrom(name);
            try {
                return (boolean) EVP_CIPHER_IS_A_FUNC.invokeExact(this.evpCipher, nameStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public boolean forEachName(Consumer<String> consumer) {
        return callNameCallback(() -> {
            try {
                return (boolean) EVP_CIPHER_NAMES_DO_ALL_FUNC.invokeExact(this.evpCipher, NAME_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }, consumer);
    }

    @Override
    public String name() {
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_CIPHER_GET0_NAME_FUNC.invokeExact(this.evpCipher);
            return nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String description() {
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_CIPHER_GET0_DESCRIPTION_FUNC.invokeExact(this.evpCipher);
            return nameSegment.address() == 0L ? null : nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String providerName() {
        OSSL_PROVIDER provider;
        try {
            provider = new OsslProvider((MemorySegment) EVP_CIPHER_GET0_PROVIDER_FUNC.invokeExact(this.evpCipher));
        } catch (Throwable t) {
            throw mapException(t);
        }
        return provider.name();
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_CIPHER_GETTABLE_PARAMS_FUNC.invokeExact(this.evpCipher));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer gettableCtxParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_CIPHER_GETTABLE_CTX_PARAMS_FUNC.invokeExact(this.evpCipher));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableCtxParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_CIPHER_SETTABLE_CTX_PARAMS_FUNC.invokeExact(this.evpCipher));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_CIPHER_GET_PARAMS_FUNC.invokeExact(this.evpCipher, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public int blockSize() {
        return this.blockSize;
    }

    @Override
    public int keyLength() {
        return this.keyLength;
    }

    @Override
    public int ivLength() {
        return this.ivLength;
    }

    @Override
    public long flags() {
        return this.flags;
    }

    @Override
    public Mode mode() {
        return this.mode;
    }
}
