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
import java.nio.ByteBuffer;

import com.oracle.jipher.internal.openssl.EVP_KDF_CTX;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DUP_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FROM_TYPE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.SIZE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentZeroize;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;

final class EvpKdfCtx implements EVP_KDF_CTX {

    static final MethodHandle EVP_KDF_CTX_NEW_FUNC;
    static final MethodHandle EVP_KDF_CTX_DUP_FUNC;
    static final MethodHandle EVP_KDF_CTX_RESET_FUNC;
    static final MethodHandle EVP_KDF_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_KDF_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_KDF_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_KDF_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_KDF_CTX_GETKDF_SIZE_FUNC;
    static final MethodHandle EVP_KDF_DERIVE_FUNC;
    static final MethodHandle EVP_KDF_CTX_FREE_FUNC;

    static {
        EVP_KDF_CTX_NEW_FUNC = downcallHandleCheckNull(
                "EVP_KDF_CTX_new", NEW_FROM_TYPE_FUNCDESC);
        EVP_KDF_CTX_DUP_FUNC = downcallHandleCheckNull(
                "EVP_KDF_CTX_dup", DUP_FUNCDESC);
        EVP_KDF_CTX_RESET_FUNC = downcallHandle(
                "EVP_KDF_CTX_reset", "(M)V");
        EVP_KDF_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_KDF_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_KDF_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_KDF_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_KDF_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_KDF_CTX_get_params", PARAMS_FUNCDESC);
        EVP_KDF_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_KDF_CTX_set_params", PARAMS_FUNCDESC);
        EVP_KDF_CTX_GETKDF_SIZE_FUNC = downcallHandle(
                "EVP_KDF_CTX_get_kdf_size", SIZE_FUNCDESC, CRITICAL);
        EVP_KDF_DERIVE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_KDF_derive", "(MMSM)I");
        EVP_KDF_CTX_FREE_FUNC = downcallHandle(
                "EVP_KDF_CTX_free", FREE_FUNCDESC);
    }

    final MemorySegment evpKdfCtx;

    EvpKdfCtx(EvpKdf type, Arena arena) {
        this(newCtx(type), arena);
    }

    EvpKdfCtx(MemorySegment evpKdfCtx, Arena arena) {
        this.evpKdfCtx = evpKdfCtx.reinterpret(arena, EvpKdfCtx::free);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_KDF_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static MemorySegment newCtx(EvpKdf type) {
        try {
            return (MemorySegment) EVP_KDF_CTX_NEW_FUNC.invokeExact(type.evpKdf);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_KDF_CTX dup(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment dupCtx;
        try {
            dupCtx = (MemorySegment) EVP_KDF_CTX_DUP_FUNC.invokeExact(this.evpKdfCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpKdfCtx(dupCtx, arena);
    }

    @Override
    public void reset() {
        try {
            EVP_KDF_CTX_RESET_FUNC.invokeExact(this.evpKdfCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_KDF_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpKdfCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_KDF_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpKdfCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_KDF_CTX_GET_PARAMS_FUNC.invokeExact(this.evpKdfCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        withDataParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_KDF_CTX_SET_PARAMS_FUNC.invokeExact(this.evpKdfCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public long kdfSize() {
        try {
            return (long) EVP_KDF_CTX_GETKDF_SIZE_FUNC.invokeExact(this.evpKdfCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    void derive(MemorySegment key, OsslParamBuffer paramBuffer) {
        if (key.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = toOffHeapSegmentZeroize(key, arena);
            long keyLen = keySeg.byteSize();
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_KDF_DERIVE_FUNC.invokeExact(this.evpKdfCtx, keySeg, keyLen, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            if (!key.isNative()) {
                MemorySegment.copy(keySeg, 0L, key, 0L, keyLen);
            }
        }
    }

    @Override
    public void derive(ByteBuffer key, OsslParamBuffer paramBuffer) {
        derive(MemorySegment.ofBuffer(key), paramBuffer);
        key.position(key.limit());
    }

    @Override
    public void derive(byte[] key, OsslParamBuffer paramBuffer) {
        derive(MemorySegment.ofArray(key), paramBuffer);
    }
}
