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

import com.oracle.jipher.internal.openssl.EVP_RAND;
import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DO_ALL_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.GET0_STRING_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.IS_A_FUNCDESC;
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

final class EvpRand implements EVP_RAND {

    static final MethodHandle EVP_RAND_UP_REF_FUNC;
    static final MethodHandle EVP_RAND_IS_A_FUNC;
    static final MethodHandle EVP_RAND_NAMES_DO_ALL_FUNC;
    static final MethodHandle EVP_RAND_GET0_NAME_FUNC;
    static final MethodHandle EVP_RAND_GET0_DESCRIPTION_FUNC;
    static final MethodHandle EVP_RAND_GET0_PROVIDER_FUNC;
    static final MethodHandle EVP_RAND_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_GETTABLE_CTX_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_SETTABLE_CTX_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_GET_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_FREE_FUNC;

    static {
        EVP_RAND_UP_REF_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_up_ref", UP_REF_FUNCDESC);
        EVP_RAND_IS_A_FUNC = downcallHandle(
                "EVP_RAND_is_a", IS_A_FUNCDESC);
        EVP_RAND_NAMES_DO_ALL_FUNC = downcallHandle(
                "EVP_RAND_names_do_all", DO_ALL_FUNCDESC);
        EVP_RAND_GET0_NAME_FUNC = downcallHandleCheckNull(
                "EVP_RAND_get0_name", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_RAND_GET0_DESCRIPTION_FUNC = downcallHandle(
                "EVP_RAND_get0_description", GET0_STRING_FUNCDESC, CRITICAL);
        EVP_RAND_GET0_PROVIDER_FUNC = downcallHandleCheckNull(
                "EVP_RAND_get0_provider", PTR_FUNCDESC, CRITICAL);
        EVP_RAND_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_RAND_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_RAND_GETTABLE_CTX_PARAMS_FUNC = downcallHandle(
                "EVP_RAND_gettable_ctx_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_RAND_SETTABLE_CTX_PARAMS_FUNC = downcallHandle(
                "EVP_RAND_settable_ctx_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_RAND_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_get_params", PARAMS_FUNCDESC);
        EVP_RAND_FREE_FUNC = downcallHandle(
                "EVP_RAND_free", FREE_FUNCDESC);
    }

    final MemorySegment evpRand;

    EvpRand(MemorySegment evpRand, Arena arena) {
        this(evpRand, arena, EvpRand::free);
    }

    EvpRand(MemorySegment evpRand, Arena arena, Consumer<MemorySegment> cleanup) {
        this.evpRand = evpRand.reinterpret(arena, cleanup);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_RAND_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_RAND upRef(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment evpRandPtr = MemorySegment.ofAddress(this.evpRand.address());
        try {
            EVP_RAND_UP_REF_FUNC.invokeExact(this.evpRand);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpRand(evpRandPtr, arena);
    }

    @Override
    public boolean isA(String name) {
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment nameStr = confinedArena.allocateFrom(name);
            try {
                return (boolean) EVP_RAND_IS_A_FUNC.invokeExact(this.evpRand, nameStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public boolean forEachName(Consumer<String> consumer) {
        return callNameCallback(() -> {
            try {
                return (boolean) EVP_RAND_NAMES_DO_ALL_FUNC.invokeExact(this.evpRand, NAME_CALLBACK_UPCALL_STUB, MemorySegment.NULL);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }, consumer);
    }

    @Override
    public String name() {
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_RAND_GET0_NAME_FUNC.invokeExact(this.evpRand);
            return nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String description() {
        try {
            MemorySegment nameSegment = (MemorySegment) EVP_RAND_GET0_DESCRIPTION_FUNC.invokeExact(this.evpRand);
            return nameSegment.address() == 0L ? null : nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public String providerName() {
        OSSL_PROVIDER provider;
        try {
            provider = new OsslProvider((MemorySegment) EVP_RAND_GET0_PROVIDER_FUNC.invokeExact(this.evpRand));
        } catch (Throwable t) {
            throw mapException(t);
        }
        return provider.name();
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_RAND_GETTABLE_PARAMS_FUNC.invokeExact(this.evpRand));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer gettableCtxParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_RAND_GETTABLE_CTX_PARAMS_FUNC.invokeExact(this.evpRand));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableCtxParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_RAND_SETTABLE_CTX_PARAMS_FUNC.invokeExact(this.evpRand));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_RAND_GET_PARAMS_FUNC.invokeExact(this.evpRand, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }
}
