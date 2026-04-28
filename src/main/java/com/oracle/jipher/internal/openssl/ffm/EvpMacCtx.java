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
import java.lang.foreign.SegmentAllocator;
import java.lang.invoke.MethodHandle;
import java.nio.ByteBuffer;
import java.util.Optional;

import com.oracle.jipher.internal.openssl.EVP_MAC_CTX;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.EVP_MD.MAX_MD_SIZE;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_SIZE_T;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DUP_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.HEAP_ACCESS;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FROM_TYPE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.SIZE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.TTSP_MAX_DATA;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegment;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_ALIGNMENT;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;
import static java.lang.Math.toIntExact;

final class EvpMacCtx extends PoolableObjectBase<EvpMacCtx> implements EVP_MAC_CTX {

    static final ObjectPool<EvpMacCtx> HMAC_MAC_CTX_OBJECT_POOL = new ObjectPool<>();

    /*
     * Pre-allocate a buffer for keys up to 64 bytes or mac values up
     * to the largest output expected for the HMAC algorithm which is
     * also the largest possible output of an approved hash function
     * (SHA-512).
     * Larger keys are still supported but won't use the pre-allocated
     * buffer.
     */
    static final long BUFFER_SIZE = Math.max(64L, MAX_MD_SIZE);

    static final long PARAM_BUFFER_SIZE = 128L;

    static final MethodHandle EVP_MAC_CTX_NEW_FUNC;
    static final MethodHandle EVP_MAC_CTX_DUP_FUNC;
    static final MethodHandle EVP_MAC_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_MAC_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_MAC_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_MAC_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_MAC_INIT_FUNC;
    static final MethodHandle EVP_MAC_CTX_GET_MAC_SIZE_FUNC;
    static final MethodHandle EVP_MAC_CTX_GET_BLOCK_SIZE_FUNC;
    static final MethodHandle EVP_MAC_UPDATE_FUNC;
    static final MethodHandle EVP_MAC_UPDATE_HEAP_FUNC;
    static final MethodHandle EVP_MAC_FINAL_FUNC;
    static final MethodHandle EVP_MAC_CTX_FREE_FUNC;

    static {
        EVP_MAC_CTX_NEW_FUNC = downcallHandleCheckNull(
                "EVP_MAC_CTX_new", NEW_FROM_TYPE_FUNCDESC);
        EVP_MAC_CTX_DUP_FUNC = downcallHandleCheckNull(
                "EVP_MAC_CTX_dup", DUP_FUNCDESC);
        EVP_MAC_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_MAC_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_MAC_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_MAC_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_MAC_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_CTX_get_params", PARAMS_FUNCDESC);
        EVP_MAC_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_CTX_set_params", PARAMS_FUNCDESC);
        EVP_MAC_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_init", "(MMSM)I");
        EVP_MAC_CTX_GET_MAC_SIZE_FUNC = downcallHandle(
                "EVP_MAC_CTX_get_mac_size", SIZE_FUNCDESC, CRITICAL);
        EVP_MAC_CTX_GET_BLOCK_SIZE_FUNC = downcallHandle(
                "EVP_MAC_CTX_get_block_size", SIZE_FUNCDESC, CRITICAL);
        EVP_MAC_UPDATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_update", "(MMS)I");
        EVP_MAC_UPDATE_HEAP_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_update", "(MMS)I", HEAP_ACCESS);
        EVP_MAC_FINAL_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MAC_final", "(MMMS)I");
        EVP_MAC_CTX_FREE_FUNC = downcallHandle(
                "EVP_MAC_CTX_free", FREE_FUNCDESC);
    }

    final MemorySegment evpMacCtx;
    final boolean releaseToHmacPool;
    final MemorySegment scratchBufSeg;
    final SegmentAllocator keyBufPA; // Prefix allocator for key buffers.
    final SegmentAllocator macBufPA; // Prefix allocator for mac buffers.
    final MemorySegment outLenSeg;
    boolean initialized;

    EvpMacCtx(EvpMac type, boolean releaseToPool, Arena arena) {
        this(newCtx(type), releaseToPool && type.isHmac, false, arena);
    }

    EvpMacCtx(MemorySegment evpMacCtx, boolean releaseToHmacPool, boolean initialized, Arena arena) {
        this.evpMacCtx = evpMacCtx.reinterpret(arena, EvpMacCtx::free);
        this.releaseToHmacPool = releaseToHmacPool;
        this.initialized = initialized;

        // The entire scratch buffer can be used for encoding params when no other slices are in use.
        long scratchBufSize = Math.max(PARAM_BUFFER_SIZE, BUFFER_SIZE + C_SIZE_T.byteSize());
        this.scratchBufSeg = arena.allocate(scratchBufSize, C_OSSL_PARAM_ALIGNMENT);
        SegmentAllocator allocator = SegmentAllocator.slicingAllocator(this.scratchBufSeg);
        // key and mac buffers overlap since no method uses both.
        SegmentAllocator bufPA = SegmentAllocator.prefixAllocator(allocator.allocate(BUFFER_SIZE));
        this.keyBufPA = bufPA;
        this.macBufPA = bufPA;
        this.outLenSeg = allocator.allocate(C_SIZE_T);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_MAC_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static MemorySegment newCtx(EvpMac type) {
        try {
            return (MemorySegment) EVP_MAC_CTX_NEW_FUNC.invokeExact(type.evpMac);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static EvpMacCtx getEvpMacCtxAutoArena(EvpMac type) {
        if (type.isHmac) {
            Optional<EvpMacCtx> macCtx = HMAC_MAC_CTX_OBJECT_POOL.pop();
            if (macCtx.isPresent()) {
                return macCtx.get();
            }
        }
        return new EvpMacCtx(type, true, Arena.ofAuto());
    }

    @Override
    public void release() {
        // Clear any sensitive data.
        if (this.initialized) {
            // Init with an arbitrary key of minimum allowed strength.
            try {
                this.init(new byte[112 * 8], OsslParamBufferImpl.EMPTY_PARAM_BUFFER);
            } catch (Exception e) {
                // Init failed. Don't release this EvpMacCtx to the hmac pool.
                return;
            }
        }

        if (this.releaseToHmacPool) {
            this.initialized = false;
            HMAC_MAC_CTX_OBJECT_POOL.push(this);
        }
    }

    @Override
    public EVP_MAC_CTX dup(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment dupCtx;
        try {
            dupCtx = (MemorySegment) EVP_MAC_CTX_DUP_FUNC.invokeExact(this.evpMacCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpMacCtx(dupCtx, false, this.initialized, arena);
    }

    @Override
    public boolean isInitialized() {
        return this.initialized;
    }

    void checkInitialized() {
        if (!this.initialized) {
            throw new IllegalStateException("Not initialized");
        }
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_MAC_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpMacCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_MAC_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpMacCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        // Use the whole of scratchBufSeg since no other slices are in use.
        withTemplateParamsSegIfNotEmpty(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
            try {
                EVP_MAC_CTX_GET_PARAMS_FUNC.invokeExact(this.evpMacCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        // Use the whole of scratchBufSeg since no other slices are in use.
        withDataParamsSegIfNotEmpty(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
            try {
                EVP_MAC_CTX_SET_PARAMS_FUNC.invokeExact(this.evpMacCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void init(byte[] key, OsslParamBuffer paramBuffer) {
        try (Arena arena = Arena.ofConfined()) {
            SegmentAllocator allocator = key == null || key.length <= BUFFER_SIZE ? this.keyBufPA : arena;
            MemorySegment keySeg = FfmOpenSsl.allocateFromNullable(key, allocator);
            long keyLen = key != null ? key.length : 0L;
            this.initialized = false;
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_MAC_INIT_FUNC.invokeExact(this.evpMacCtx, keySeg, keyLen, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            this.initialized = true;
        }
    }

    @Override
    public long macSize() {
        try {
            return (long) EVP_MAC_CTX_GET_MAC_SIZE_FUNC.invokeExact(this.evpMacCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public long blockSize() {
        try {
            return (long) EVP_MAC_CTX_GET_BLOCK_SIZE_FUNC.invokeExact(this.evpMacCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    void update(MemorySegment in) {
        checkInitialized();
        try {
            if (in.isNative()) {
                EVP_MAC_UPDATE_FUNC.invokeExact(this.evpMacCtx, in, in.byteSize());
            } else {
                while (in.byteSize() > 0L) {
                    long chunkSize = Math.min(in.byteSize(), TTSP_MAX_DATA);
                    EVP_MAC_UPDATE_HEAP_FUNC.invokeExact(this.evpMacCtx, in, chunkSize);
                    in = in.asSlice(chunkSize);
                }
            }
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void update(ByteBuffer in) {
        update(MemorySegment.ofBuffer(in));
        in.position(in.limit());
    }

    @Override
    public void update(byte[] in, int inOffset, int inLen) {
        update(MemorySegment.ofArray(in).asSlice(inOffset, inLen));
    }

    long doFinal(MemorySegment out) {
        checkInitialized();
        if (out.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }

        // If out is not NULL, check that out is of sufficient size to receive the output.
        // Prior to commit 4fffef3dedcb80d2bfa657d4b7c2850dddaef1b4 OpenSSL failed to ensure
        // that the outsize for the buffer is large enough for the MAC output.
        // The bug fix first appeared in OpenSSL 3.0.1.
        // Hence, the java layer must ensure that it always provides OpenSSL with a buffer large
        // enough for the MAC output.
        if (!out.isNative() || out.address() != 0L) {
            if (out.byteSize() < macSize()) {
                throw new IndexOutOfBoundsException("Output buffer is of insufficient size");
            }
            out = out.asSlice(0L, macSize());
        }

        MemorySegment outSeg = toOffHeapSegment(out, this.macBufPA);
        try {
            EVP_MAC_FINAL_FUNC.invokeExact(this.evpMacCtx, outSeg, this.outLenSeg, outSeg.byteSize());
        } catch (Throwable t) {
            throw mapException(t);
        }
        long n = this.outLenSeg.get(C_SIZE_T, 0L);

        if (!out.isNative()) {
            MemorySegment.copy(outSeg, 0L, out, 0L, n);
        }
        return n;
    }

    @Override
    public int doFinal(byte[] out, int outOffset) {
        MemorySegment outSeg = out != null ? MemorySegment.ofArray(out).asSlice(outOffset) : MemorySegment.NULL;
        return toIntExact(doFinal(outSeg));
    }
}
