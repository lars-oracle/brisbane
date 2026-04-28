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
import java.security.SignatureException;
import java.util.function.Consumer;

import com.oracle.jipher.internal.openssl.EVP_MD;
import com.oracle.jipher.internal.openssl.EVP_MD_CTX;
import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.EVP_PKEY_CTX;
import com.oracle.jipher.internal.openssl.OSSL_LIB_CTX;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.EVP_MD.MAX_MD_SIZE;
import static com.oracle.jipher.internal.openssl.ffm.ErrorQueueUtil.checkThrowSignatureVerifyException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.COPY_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_INT;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_POINTER;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_SIZE_T;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.INT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.HEAP_ACCESS;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.NEW_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.TTSP_MAX_DATA;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.constString;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.newOpenSslException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegment;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentCopy;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentCopyZeroize;
import static com.oracle.jipher.internal.openssl.ffm.OsslParam.C_OSSL_PARAM_ALIGNMENT;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSeg;
import static java.lang.Math.toIntExact;

final class EvpMdCtx extends PoolableObjectBase<EvpMdCtx> implements EVP_MD_CTX {

    static final ObjectPool<EvpMdCtx> MD_CTX_OBJECT_POOL = new ObjectPool<>();

    static final long PARAM_BUFFER_SIZE = 128L;

    static final MethodHandle EVP_MD_CTX_NEW_FUNC;
    static final MethodHandle EVP_MD_CTX_COPY_EX_FUNC;
    static final MethodHandle EVP_MD_CTX_RESET_FUNC;
    static final MethodHandle EVP_MD_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_MD_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_MD_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_MD_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_DIGEST_INIT_EX2_FUNC;
    static final MethodHandle EVP_DIGEST_UPDATE_FUNC;
    static final MethodHandle EVP_DIGEST_UPDATE_HEAP_FUNC;
    static final MethodHandle EVP_DIGEST_FINAL_EX_FUNC;

    static final MethodHandle EVP_DIGEST_SIGN_INIT_EX_FUNC;
    static final MethodHandle EVP_DIGEST_SIGN_UPDATE_FUNC;
    static final MethodHandle EVP_DIGEST_SIGN_UPDATE_HEAP_FUNC;
    static final MethodHandle EVP_DIGEST_SIGN_FINAL_FUNC;
    static final MethodHandle EVP_DIGEST_SIGN_FUNC;
    static final MethodHandle EVP_DIGEST_VERIFY_INIT_EX_FUNC;
    static final MethodHandle EVP_DIGEST_VERIFY_UPDATE_FUNC;
    static final MethodHandle EVP_DIGEST_VERIFY_UPDATE_HEAP_FUNC;
    static final MethodHandle EVP_DIGEST_VERIFY_FINAL_FUNC;
    static final MethodHandle EVP_DIGEST_VERIFY_FUNC;

    static final MethodHandle EVP_MD_CTX_FREE_FUNC;

    static {
        EVP_MD_CTX_NEW_FUNC = downcallHandleCheckNull(
                "EVP_MD_CTX_new", NEW_FUNCDESC);
        EVP_MD_CTX_COPY_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MD_CTX_copy_ex", COPY_FUNCDESC);
        EVP_MD_CTX_RESET_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MD_CTX_reset", INT_FUNCDESC);
        EVP_MD_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_MD_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_MD_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_MD_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_MD_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MD_CTX_get_params", PARAMS_FUNCDESC);
        EVP_MD_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_MD_CTX_set_params", PARAMS_FUNCDESC);
        EVP_DIGEST_INIT_EX2_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestInit_ex2", "(MMM)I");
        EVP_DIGEST_UPDATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestUpdate", "(MMS)I");
        EVP_DIGEST_UPDATE_HEAP_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestUpdate", "(MMS)I", HEAP_ACCESS);
        EVP_DIGEST_FINAL_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestFinal_ex", "(MMM)I");
        EVP_DIGEST_SIGN_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestSignInit_ex", "(MMMMMMM)I");
        EVP_DIGEST_SIGN_UPDATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestSignUpdate", "(MMS)I");
        EVP_DIGEST_SIGN_UPDATE_HEAP_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestSignUpdate", "(MMS)I", HEAP_ACCESS);
        EVP_DIGEST_SIGN_FINAL_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestSignFinal", "(MMM)I");
        EVP_DIGEST_SIGN_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestSign", "(MMMMS)I");
        EVP_DIGEST_VERIFY_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestVerifyInit_ex", "(MMMMMMM)I");
        EVP_DIGEST_VERIFY_UPDATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestVerifyUpdate", "(MMS)I");
        EVP_DIGEST_VERIFY_UPDATE_HEAP_FUNC = downcallHandleCheckZeroNeg(
                "EVP_DigestVerifyUpdate", "(MMS)I", HEAP_ACCESS);
        EVP_DIGEST_VERIFY_FINAL_FUNC = downcallHandle(
                "EVP_DigestVerifyFinal", "(MMS)I");
        EVP_DIGEST_VERIFY_FUNC = downcallHandle(
                "EVP_DigestVerify", "(MMSMS)I");
        EVP_MD_CTX_FREE_FUNC = downcallHandle(
                "EVP_MD_CTX_free", FREE_FUNCDESC);
    }

    final MemorySegment evpMdCtx;
    final boolean releaseToPool;
    final MemorySegment scratchBufSeg;
    final SegmentAllocator digestBufPA; // Prefix allocator for digest buffers.
    final MemorySegment sigLenSeg;
    final MemorySegment outLenSeg;
    boolean initialized;
    int blockSize;
    int size;

    EvpMdCtx(boolean releaseToPool, Arena arena) {
        MemorySegment evpMdCtx;
        try {
            evpMdCtx = (MemorySegment) EVP_MD_CTX_NEW_FUNC.invokeExact();
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.evpMdCtx = evpMdCtx.reinterpret(arena, EvpMdCtx::free);
        this.releaseToPool = releaseToPool;
        this.initialized = false;

        // The entire scratch buffer can be used for encoding params when no other slices are in use.
        long scratchBufSize = Math.max(PARAM_BUFFER_SIZE, MAX_MD_SIZE + C_SIZE_T.byteSize() + C_INT.byteSize());
        this.scratchBufSeg = arena.allocate(scratchBufSize, C_OSSL_PARAM_ALIGNMENT);
        SegmentAllocator allocator = SegmentAllocator.slicingAllocator(this.scratchBufSeg);
        this.digestBufPA = SegmentAllocator.prefixAllocator(allocator.allocate(MAX_MD_SIZE));
        this.sigLenSeg = allocator.allocate(C_SIZE_T);
        this.outLenSeg = allocator.allocate(C_INT);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_MD_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static EvpMdCtx getEvpMdCtxAutoArena() {
        return MD_CTX_OBJECT_POOL.pop().orElseGet(() -> new EvpMdCtx(true, Arena.ofAuto()));
    }

    @Override
    public void release() {
        // Clear any sensitive data.
        reset();

        if (this.releaseToPool) {
            MD_CTX_OBJECT_POOL.push(this);
        }
    }

    @Override
    public EVP_MD_CTX dup(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        EvpMdCtx dupCtx = new EvpMdCtx(false, arena);
        dupCtx.copy(this);
        return dupCtx;
    }

    @Override
    public EVP_MD_CTX dup() {
        EvpMdCtx dupCtx = getEvpMdCtxAutoArena();
        dupCtx.copy(this);
        return dupCtx;
    }

    void copy(EvpMdCtx ctx) {
        try {
            EVP_MD_CTX_COPY_EX_FUNC.invokeExact(this.evpMdCtx, ctx.evpMdCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        this.initialized = ctx.initialized;
        this.blockSize = ctx.blockSize;
        this.size = ctx.size;
    }

    @Override
    public void reset() {
        this.initialized = false;
        try {
            EVP_MD_CTX_RESET_FUNC.invokeExact(this.evpMdCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
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
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_MD_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpMdCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_MD_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpMdCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        if (paramBuffer.count() > 0) {
            // OpenSSL 3.0.x versions < 3.0.9 and OpenSSL 3.1.x versions < 3.1.1 have an issue
            // where EVP_MD_CTX_get_params will cause a crash due to dereferencing a null
            // function pointer in a situation where it should detect that the algorithm doesn't
            // support get_params and then indicate an error has occurred by returning zero.
            // The issue is fixed in commit 5fbf6dd.
            // https://github.com/openssl/openssl/commit/5fbf6dd009fe23fcbd040eed058dd6b5f4d2e717
            if (gettableParams().count() == 0) {
                // get_params is not supported.
                // Avoid calling EVP_MD_CTX_get_params and immediately throw the OpenSslException
                // that should normally be thrown as a result of invoking EVP_MD_CTX_get_params.
                throw FfmOpenSsl.newOpenSslException("EVP_MD_CTX_get_params");
            }

            // Use the whole of scratchBufSeg since no other slices are in use.
            withTemplateParamsSeg(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
                try {
                    EVP_MD_CTX_GET_PARAMS_FUNC.invokeExact(this.evpMdCtx, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
        }
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        // Use the whole of scratchBufSeg since no other slices are in use.
        withDataParamsSegIfNotEmpty(paramBuffer, this.scratchBufSeg, (paramsSeg) -> {
            try {
                EVP_MD_CTX_SET_PARAMS_FUNC.invokeExact(this.evpMdCtx, paramsSeg);
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
    public int size() {
        return this.size;
    }

    @Override
    public void init(EVP_MD type, OsslParamBuffer paramBuffer) {
        init((EvpMd) type, paramBuffer);
    }

    void init(EvpMd type, OsslParamBuffer paramBuffer) {
        MemorySegment md;
        if (type != null) {
            this.blockSize = type.blockSize;
            this.size = type.size;
            md = type.evpMd;
        } else {
            md = MemorySegment.NULL;
        }
        this.initialized = false;
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_DIGEST_INIT_EX2_FUNC.invokeExact(this.evpMdCtx, md, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
        this.initialized = true;
    }

    void update(MemorySegment in) {
        checkInitialized();
        try {
            if (in.isNative()) {
                EVP_DIGEST_UPDATE_FUNC.invokeExact(this.evpMdCtx, in, in.byteSize());
            } else {
                while (in.byteSize() > 0L) {
                    long chunkSize = Math.min(in.byteSize(), TTSP_MAX_DATA);
                    EVP_DIGEST_UPDATE_HEAP_FUNC.invokeExact(this.evpMdCtx, in, chunkSize);
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

    int digestFinal(MemorySegment out) {
        checkInitialized();
        if (out.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }

        // Check that the output buffer has sufficient space to receive the digest.
        if (out.byteSize() < this.size) {
            throw new IndexOutOfBoundsException("Insufficient space available in output buffer (" +
                    out.byteSize() + " bytes available, " + this.size + " bytes required)");
        }
        out = out.asSlice(0L, this.size);

        MemorySegment outSeg = toOffHeapSegment(out, this.digestBufPA);
        this.initialized = false;
        try {
            EVP_DIGEST_FINAL_EX_FUNC.invokeExact(this.evpMdCtx, outSeg, this.outLenSeg);
        } catch (Throwable t) {
            throw mapException(t);
        }
        int n = this.outLenSeg.get(C_INT, 0L);

        if (!out.isNative()) {
            MemorySegment.copy(outSeg, 0L, out, 0L, n);
        }
        return n;
    }

    @Override
    public int digestFinal(byte[] out, int outOffset) {
        return digestFinal(MemorySegment.ofArray(out).asSlice(outOffset));
    }

    @Override
    public void signInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OsslParamBuffer paramBuffer) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment evpPkeyCtxPtrSeg = evpPkeyCtxConsumer != null ? arena.allocate(C_POINTER) : MemorySegment.NULL;
            MemorySegment mdNameStr = mdName != null ? constString(mdName) : MemorySegment.NULL;
            MemorySegment osslLibCtx = libCtx != null ? ((OsslLibCtx) libCtx).osslLibCtx : MemorySegment.NULL;
            MemorySegment propertiesStr = properties != null ? arena.allocateFrom(properties) : MemorySegment.NULL;
            MemorySegment evpPkey = pkey != null ? ((EvpPkey) pkey).upRefInternal(arena).evpPkey : MemorySegment.NULL;
            this.initialized = false;
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_DIGEST_SIGN_INIT_EX_FUNC.invokeExact(this.evpMdCtx, evpPkeyCtxPtrSeg, mdNameStr, osslLibCtx, propertiesStr, evpPkey, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            if (evpPkeyCtxConsumer != null) {
                MemorySegment evpPkeyCtx = evpPkeyCtxPtrSeg.get(C_POINTER, 0L);
                if (evpPkeyCtx.address() == 0L) {
                    throw newOpenSslException("EVP_DigestSignInit_ex: out ctx is NULL,");
                }
                evpPkeyCtxConsumer.accept(new EvpPkeyCtx(evpPkeyCtx, arena, null));
            }
            this.initialized = true;
        }
    }

    void signUpdate(MemorySegment data) {
        checkInitialized();
        try {
            if (data.isNative()) {
                EVP_DIGEST_SIGN_UPDATE_FUNC.invokeExact(this.evpMdCtx, data, data.byteSize());
            } else {
                while (data.byteSize() > 0L) {
                    long chunkSize = Math.min(data.byteSize(), TTSP_MAX_DATA);
                    EVP_DIGEST_SIGN_UPDATE_HEAP_FUNC.invokeExact(this.evpMdCtx, data, chunkSize);
                    data = data.asSlice(chunkSize);
                }
            }
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void signUpdate(byte[] data, int dataOffset, int dataLen) {
        signUpdate(MemorySegment.ofArray(data).asSlice(dataOffset, dataLen));
    }

    @Override
    public void signUpdate(ByteBuffer data) {
        signUpdate(MemorySegment.ofBuffer(data));
        data.position(data.limit());
    }

    long signFinal(MemorySegment sig) {
        checkInitialized();
        if (sig.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment sigSeg = toOffHeapSegment(sig, arena);
            // sigSeg.byteSize() == 0L when sigSeg == MemorySegment.NULL
            this.sigLenSeg.set(C_SIZE_T, 0L, sigSeg.byteSize());
            try {
                EVP_DIGEST_SIGN_FINAL_FUNC.invokeExact(this.evpMdCtx, sigSeg, this.sigLenSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
            long sigLen = this.sigLenSeg.get(C_SIZE_T, 0L);

            if (!sig.isNative() || sig.address() != 0L) {
                if (sigLen > sigSeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!sig.isNative()) {
                    MemorySegment.copy(sigSeg, 0L, sig, 0L, sigLen);
                }
            }

            return sigLen;
        }
    }

    @Override
    public int signFinal(byte[] sig, int sigOffset) {
        MemorySegment sigSeg = sig != null ? MemorySegment.ofArray(sig).asSlice(sigOffset) : MemorySegment.NULL;
        return toIntExact(signFinal(sigSeg));
    }

    long sign(MemorySegment tbs, MemorySegment sig) {
        checkInitialized();
        if (sig.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment tbsSeg = toOffHeapSegmentCopyZeroize(tbs, arena);
            MemorySegment sigSeg = toOffHeapSegment(sig, arena);
            // sigSeg.byteSize() == 0L when sigSeg == MemorySegment.NULL
            this.sigLenSeg.set(C_SIZE_T, 0L, sigSeg.byteSize());
            try {
                // tbsSeg.byteSize() == 0L when tbsSeg == MemorySegment.NULL
                EVP_DIGEST_SIGN_FUNC.invokeExact(this.evpMdCtx, sigSeg, this.sigLenSeg, tbsSeg, tbsSeg.byteSize());
            } catch (Throwable t) {
                this.initialized = false;
                throw mapException(t);
            }
            long sigLen = this.sigLenSeg.get(C_SIZE_T, 0L);

            if (!sig.isNative() || sig.address() != 0L) {
                if (sigLen > sigSeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!sig.isNative()) {
                    MemorySegment.copy(sigSeg, 0L, sig, 0L, sigLen);
                }
            }

            return sigLen;
        }
    }

    @Override
    public int sign(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset) {
        MemorySegment tbsSeg;
        MemorySegment sigSeg;
        if (sig == null) {
            tbsSeg = MemorySegment.NULL;
            sigSeg = MemorySegment.NULL;
        } else {
            tbsSeg = MemorySegment.ofArray(tbs).asSlice(tbsOffset, tbsLen);
            sigSeg = MemorySegment.ofArray(sig).asSlice(sigOffset);
        }
        return toIntExact(sign(tbsSeg, sigSeg));
    }

    @Override
    public void verifyInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OsslParamBuffer paramBuffer) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment evpPkeyCtxPtrSeg = evpPkeyCtxConsumer != null ? arena.allocate(C_POINTER) : MemorySegment.NULL;
            MemorySegment mdNameStr = mdName != null ? constString(mdName) : MemorySegment.NULL;
            MemorySegment osslLibCtx = libCtx != null ? ((OsslLibCtx) libCtx).osslLibCtx : MemorySegment.NULL;
            MemorySegment propertiesStr = properties != null ? arena.allocateFrom(properties) : MemorySegment.NULL;
            MemorySegment evpPkey = pkey != null ? ((EvpPkey) pkey).upRefInternal(arena).evpPkey : MemorySegment.NULL;
            this.initialized = false;
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_DIGEST_VERIFY_INIT_EX_FUNC.invokeExact(this.evpMdCtx, evpPkeyCtxPtrSeg, mdNameStr, osslLibCtx, propertiesStr, evpPkey, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            if (evpPkeyCtxConsumer != null) {
                MemorySegment evpPkeyCtx = evpPkeyCtxPtrSeg.get(C_POINTER, 0L);
                if (evpPkeyCtx.address() == 0L) {
                    throw newOpenSslException("EVP_DigestVerifyInit_ex: out ctx is NULL,");
                }
                evpPkeyCtxConsumer.accept(new EvpPkeyCtx(evpPkeyCtx, arena, null));
            }
            this.initialized = true;
        }
    }

    void verifyUpdate(MemorySegment data) {
        checkInitialized();
        try {
            if (data.isNative()) {
                EVP_DIGEST_VERIFY_UPDATE_FUNC.invokeExact(this.evpMdCtx, data, data.byteSize());
            } else {
                while (data.byteSize() > 0L) {
                    long chunkSize = Math.min(data.byteSize(), TTSP_MAX_DATA);
                    EVP_DIGEST_VERIFY_UPDATE_HEAP_FUNC.invokeExact(this.evpMdCtx, data, chunkSize);
                    data = data.asSlice(chunkSize);
                }
            }
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void verifyUpdate(byte[] data, int dataOffset, int dataLen) {
        verifyUpdate(MemorySegment.ofArray(data).asSlice(dataOffset, dataLen));
    }

    @Override
    public void verifyUpdate(ByteBuffer data) {
        verifyUpdate(MemorySegment.ofBuffer(data));
        data.position(data.limit());
    }

    boolean verifyFinal(MemorySegment sig) throws SignatureException {
        checkInitialized();
        try (Arena arena = Arena.ofConfined()) {
            int ret;
            MemorySegment sigSeg = toOffHeapSegmentCopy(sig, arena);
            try {
                ret = (int) EVP_DIGEST_VERIFY_FINAL_FUNC.invokeExact(this.evpMdCtx, sigSeg, sig.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            if (ret != 1) {
                checkThrowSignatureVerifyException("EVP_DigestVerifyFinal", ret);
            }
            return ret == 1;
        }
    }

    @Override
    public boolean verifyFinal(byte[] sig, int sigOffset, int sigLen) throws SignatureException {
        MemorySegment sigSeg = MemorySegment.ofArray(sig).asSlice(sigOffset, sigLen);
        return verifyFinal(sigSeg);
    }

    boolean verify(MemorySegment tbs, MemorySegment sig) throws SignatureException {
        checkInitialized();
        try (Arena arena = Arena.ofConfined()) {
            int ret;
            MemorySegment tbsSeg = toOffHeapSegmentCopyZeroize(tbs, arena);
            MemorySegment sigSeg = toOffHeapSegmentCopy(sig, arena);
            try {
                ret = (int) EVP_DIGEST_VERIFY_FUNC.invokeExact(this.evpMdCtx, sigSeg, sig.byteSize(), tbsSeg, tbsSeg.byteSize());
            } catch (Throwable t) {
                this.initialized = false;
                throw mapException(t);
            }
            if (ret != 1) {
                checkThrowSignatureVerifyException("EVP_DigestVerify", ret);
            }
            return ret == 1;
        }
    }

    @Override
    public boolean verify(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset, int sigLen) throws SignatureException {
        MemorySegment tbsSeg = MemorySegment.ofArray(tbs).asSlice(tbsOffset, tbsLen);
        MemorySegment sigSeg = MemorySegment.ofArray(sig).asSlice(sigOffset, sigLen);
        return verify(tbsSeg, sigSeg);
    }
}
