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

import com.oracle.jipher.internal.openssl.EVP_RAND_CTX;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.INT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FROM_TYPE_AND_PARENT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;
import static java.lang.foreign.ValueLayout.JAVA_BYTE;

final class EvpRandCtx implements EVP_RAND_CTX {

    static final MethodHandle EVP_RAND_CTX_NEW_FUNC;
    static final MethodHandle EVP_RAND_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_RAND_INSTANTIATE_FUNC;
    static final MethodHandle EVP_RAND_UNINSTANTIATE_FUNC;
    static final MethodHandle EVP_RAND_GENERATE_FUNC;
    static final MethodHandle EVP_RAND_RESEED_FUNC;
    static final MethodHandle EVP_RAND_ENABLE_LOCKING_FUNC;
    static final MethodHandle EVP_RAND_GET_STRENGTH_FUNC;
    static final MethodHandle EVP_RAND_GET_STATE_FUNC;
    static final MethodHandle EVP_RAND_CTX_FREE_FUNC;

    static {
        EVP_RAND_CTX_NEW_FUNC = downcallHandleCheckNull(
                "EVP_RAND_CTX_new", NEW_FROM_TYPE_AND_PARENT_FUNCDESC);
        EVP_RAND_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_RAND_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_RAND_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_RAND_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_RAND_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_CTX_get_params", PARAMS_FUNCDESC);
        EVP_RAND_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_CTX_set_params", PARAMS_FUNCDESC);
        EVP_RAND_INSTANTIATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_instantiate", "(MIIMSM)I");
        EVP_RAND_UNINSTANTIATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_uninstantiate", INT_FUNCDESC);
        EVP_RAND_GENERATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_generate", "(MMSIIMS)I");
        EVP_RAND_RESEED_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_reseed", "(MIMSMS)I");
        EVP_RAND_ENABLE_LOCKING_FUNC = downcallHandleCheckZeroNeg(
                "EVP_RAND_enable_locking", INT_FUNCDESC);
        EVP_RAND_GET_STRENGTH_FUNC = downcallHandle(
                "EVP_RAND_get_strength", INT_FUNCDESC, CRITICAL);
        EVP_RAND_GET_STATE_FUNC = downcallHandle(
                "EVP_RAND_get_state", INT_FUNCDESC, CRITICAL);
        EVP_RAND_CTX_FREE_FUNC = downcallHandle(
                "EVP_RAND_CTX_free", FREE_FUNCDESC);
    }

    final MemorySegment evpRandCtx;

    EvpRandCtx(EvpRand type, EvpRandCtx parent, Arena arena) {
        this(type, parent != null ? parent.evpRandCtx : MemorySegment.NULL, arena);
    }

    EvpRandCtx(EvpRand type, MemorySegment parentSeg, Arena arena) {
        MemorySegment evpRandCtx;
        try {
            evpRandCtx = (MemorySegment) EVP_RAND_CTX_NEW_FUNC.invokeExact(type.evpRand, parentSeg);
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.evpRandCtx = evpRandCtx.reinterpret(arena, EvpRandCtx::free);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_RAND_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_RAND_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpRandCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_RAND_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpRandCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_RAND_CTX_GET_PARAMS_FUNC.invokeExact(this.evpRandCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        withDataParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_RAND_CTX_SET_PARAMS_FUNC.invokeExact(this.evpRandCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void instantiate(int strength, boolean predictionResistance, byte[] pStr, OsslParamBuffer paramBuffer) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment pStrSeg = FfmOpenSsl.allocateFromNullable(pStr, arena);
            long pStrLen = pStr != null ? pStr.length : 0L;
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_RAND_INSTANTIATE_FUNC.invokeExact(this.evpRandCtx, strength, predictionResistance ? 1 : 0, pStrSeg, pStrLen, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
        }
    }

    @Override
    public void uninstantiate() {
        try {
            EVP_RAND_UNINSTANTIATE_FUNC.invokeExact(this.evpRandCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void generate(byte[] out, int strength, boolean predictionResistance,  byte[] addIn) {
        try (Arena arena = Arena.ofConfined()) {
            long outLen = out.length;
            MemorySegment outSeg = OpenSslAllocators.mallocClearFree(outLen, arena);
            MemorySegment addInSeg = FfmOpenSsl.allocateFromNullable(addIn, arena);
            long addInLen = addIn != null ? addIn.length : 0L;
            try {
                EVP_RAND_GENERATE_FUNC.invokeExact(this.evpRandCtx, outSeg, outLen, strength, predictionResistance ? 1 : 0, addInSeg, addInLen);
            } catch (Throwable t) {
                throw mapException(t);
            }
            MemorySegment.copy(outSeg, JAVA_BYTE, 0L, out, 0, out.length);
        }
    }

    @Override
    public void reseed(boolean predictionResistance, byte[] entropy, byte[] addIn) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment entropySeg = FfmOpenSsl.allocateFromNullable(entropy, arena);
            long entropyLen = entropy != null ? entropy.length : 0L;
            MemorySegment addInSeg = FfmOpenSsl.allocateFromNullable(addIn, arena);
            long addInLen = addIn != null ? addIn.length : 0L;
            try {
                EVP_RAND_RESEED_FUNC.invokeExact(this.evpRandCtx, predictionResistance ? 1 : 0, entropySeg, entropyLen, addInSeg, addInLen);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public void enableLocking() {
        try {
            EVP_RAND_ENABLE_LOCKING_FUNC.invokeExact(this.evpRandCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public int strength() {
        try {
            return (int) EVP_RAND_GET_STRENGTH_FUNC.invokeExact(this.evpRandCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public State state() {
        try {
            return State.values()[(int) EVP_RAND_GET_STATE_FUNC.invokeExact(this.evpRandCtx)];
        } catch (Throwable t) {
            throw mapException(t);
        }
    }
}
