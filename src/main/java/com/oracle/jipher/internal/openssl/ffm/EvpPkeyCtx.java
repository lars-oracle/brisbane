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
import java.security.SignatureException;
import java.util.function.Consumer;

import com.oracle.jipher.internal.openssl.EVP_PKEY;
import com.oracle.jipher.internal.openssl.EVP_PKEY.Selection;
import com.oracle.jipher.internal.openssl.EVP_PKEY_CTX;
import com.oracle.jipher.internal.openssl.OsslArena;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.ErrorQueueUtil.checkThrowSignatureVerifyException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_POINTER;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.C_SIZE_T;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.DUP_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.FREE_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.INT_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.IS_A_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.OPTIONAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_SELECTED_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.newOpenSslException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegment;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentCopy;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentCopyZeroize;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.toOffHeapSegmentZeroize;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSeg;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withDataParamsSegIfNotEmpty;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;
import static java.lang.Math.toIntExact;

final class EvpPkeyCtx implements EVP_PKEY_CTX {

    static final MethodHandle EVP_PKEY_CTX_DUP_FUNC;
    static final MethodHandle EVP_PKEY_CTX_IS_A_FUNC;
    static final MethodHandle EVP_PKEY_CTX_GETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_CTX_SETTABLE_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_FROMDATA_SETTABLE_FUNC;
    static final MethodHandle EVP_PKEY_CTX_GET_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_CTX_SET_PARAMS_FUNC;
    static final MethodHandle EVP_PKEY_FROMDATA_INIT_FUNC;
    static final MethodHandle EVP_PKEY_FROMDATA_FUNC;
    static final MethodHandle EVP_PKEY_CTX_FREE_FUNC;

    static final MethodHandle EVP_PKEY_ENCRYPT_INIT_EX_FUNC;
    static final MethodHandle EVP_PKEY_ENCRYPT_FUNC;
    static final MethodHandle EVP_PKEY_DECRYPT_INIT_EX_FUNC;
    static final MethodHandle EVP_PKEY_DECRYPT_FUNC;

    static final MethodHandle EVP_PKEY_DERIVE_INIT_EX_FUNC;
    static final MethodHandle EVP_PKEY_DERIVE_SET_PEER_EX_FUNC;
    static final MethodHandle EVP_PKEY_DERIVE_FUNC;

    static final MethodHandle EVP_PKEY_KEYGEN_INIT_FUNC;
    static final MethodHandle EVP_PKEY_PARAMGEN_INIT_FUNC;
    static final MethodHandle EVP_PKEY_GENERATE_FUNC;

    static final MethodHandle EVP_PKEY_SIGN_INIT_EX_FUNC;
    static final MethodHandle EVP_PKEY_SIGN_MESSAGE_INIT_FUNC;
    static final MethodHandle EVP_PKEY_SIGN_FUNC;
    static final MethodHandle EVP_PKEY_VERIFY_INIT_EX_FUNC;
    static final MethodHandle EVP_PKEY_VERIFY_MESSAGE_INIT_FUNC;
    static final MethodHandle EVP_PKEY_VERIFY_FUNC;

    static final MethodHandle EVP_PKEY_ENCAPSULATE_INIT_FUNC;
    static final MethodHandle EVP_PKEY_ENCAPSULATE_FUNC;
    static final MethodHandle EVP_PKEY_DECAPSULATE_INIT_FUNC;
    static final MethodHandle EVP_PKEY_DECAPSULATE_FUNC;

    static {
        EVP_PKEY_CTX_DUP_FUNC = downcallHandleCheckNull(
                "EVP_PKEY_CTX_dup", DUP_FUNCDESC);
        EVP_PKEY_CTX_IS_A_FUNC = downcallHandle(
                "EVP_PKEY_CTX_is_a", IS_A_FUNCDESC);
        EVP_PKEY_CTX_GETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_PKEY_CTX_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_PKEY_CTX_SETTABLE_PARAMS_FUNC = downcallHandle(
                "EVP_PKEY_CTX_settable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_PKEY_FROMDATA_SETTABLE_FUNC = downcallHandle(
                "EVP_PKEY_fromdata_settable", RETURN_SELECTED_CONST_PARAMS_FUNCDESC, CRITICAL);
        EVP_PKEY_CTX_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_CTX_get_params", PARAMS_FUNCDESC);
        EVP_PKEY_CTX_SET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_CTX_set_params", PARAMS_FUNCDESC);
        EVP_PKEY_FROMDATA_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_fromdata_init", INT_FUNCDESC);
        EVP_PKEY_FROMDATA_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_fromdata", "(MMIM)I");
        EVP_PKEY_CTX_FREE_FUNC = downcallHandle(
                "EVP_PKEY_CTX_free", FREE_FUNCDESC);

        EVP_PKEY_ENCRYPT_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_encrypt_init_ex", PARAMS_FUNCDESC);
        EVP_PKEY_ENCRYPT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_encrypt", "(MMMMS)I");
        EVP_PKEY_DECRYPT_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_decrypt_init_ex", PARAMS_FUNCDESC);
        EVP_PKEY_DECRYPT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_decrypt", "(MMMMS)I");

        EVP_PKEY_DERIVE_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_derive_init_ex", PARAMS_FUNCDESC);
        EVP_PKEY_DERIVE_SET_PEER_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_derive_set_peer_ex", "(MMI)I");
        EVP_PKEY_DERIVE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_derive", "(MMM)I");

        EVP_PKEY_KEYGEN_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_keygen_init", INT_FUNCDESC);
        EVP_PKEY_PARAMGEN_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_paramgen_init", INT_FUNCDESC);
        EVP_PKEY_GENERATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_generate", "(MM)I");

        EVP_PKEY_SIGN_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_sign_init_ex", PARAMS_FUNCDESC);
        EVP_PKEY_SIGN_MESSAGE_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_sign_message_init", "(MMM)I", OPTIONAL);
        EVP_PKEY_SIGN_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_sign", "(MMMMS)I");
        EVP_PKEY_VERIFY_INIT_EX_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_verify_init_ex", PARAMS_FUNCDESC);
        EVP_PKEY_VERIFY_MESSAGE_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_verify_message_init", "(MMM)I", OPTIONAL);
        EVP_PKEY_VERIFY_FUNC = downcallHandle(
                "EVP_PKEY_verify", "(MMSMS)I");

        EVP_PKEY_ENCAPSULATE_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_encapsulate_init", PARAMS_FUNCDESC);
        EVP_PKEY_ENCAPSULATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_encapsulate", "(MMMMM)I");
        EVP_PKEY_DECAPSULATE_INIT_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_decapsulate_init", PARAMS_FUNCDESC);
        EVP_PKEY_DECAPSULATE_FUNC = downcallHandleCheckZeroNeg(
                "EVP_PKEY_decapsulate", "(MMMMS)I");
    }

    final MemorySegment evpPkeyCtx;

    EvpPkeyCtx(MemorySegment evpPkeyCtx, Arena arena) {
        this(evpPkeyCtx, arena, EvpPkeyCtx::free);
    }

    EvpPkeyCtx(MemorySegment evpPkeyCtx, Arena arena, Consumer<MemorySegment> cleanup) {
        this.evpPkeyCtx = evpPkeyCtx.reinterpret(arena, cleanup);
    }

    static void free(MemorySegment seg) {
        try {
            EVP_PKEY_CTX_FREE_FUNC.invokeExact(seg);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_PKEY_CTX dup(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        MemorySegment dupCtx;
        try {
            dupCtx = (MemorySegment) EVP_PKEY_CTX_DUP_FUNC.invokeExact(this.evpPkeyCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
        return new EvpPkeyCtx(dupCtx, arena);
    }

    @Override
    public boolean isA(String name) {
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment nameStr = confinedArena.allocateFrom(name);
            try {
                return (boolean) EVP_PKEY_CTX_IS_A_FUNC.invokeExact(this.evpPkeyCtx, nameStr);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_PKEY_CTX_GETTABLE_PARAMS_FUNC.invokeExact(this.evpPkeyCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer settableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_PKEY_CTX_SETTABLE_PARAMS_FUNC.invokeExact(this.evpPkeyCtx));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer fromdataSettableParams(Selection selection) {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) EVP_PKEY_FROMDATA_SETTABLE_FUNC.invokeExact(this.evpPkeyCtx, selection.mask));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_CTX_GET_PARAMS_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void setParams(OsslParamBuffer paramBuffer) {
        withDataParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_CTX_SET_PARAMS_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void fromdataInit() {
        try {
            EVP_PKEY_FROMDATA_INIT_FUNC.invokeExact(this.evpPkeyCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_PKEY fromdata(Selection selection, OsslArena osslArena, OsslParamBuffer paramBuffer) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment evpPkeyPtrSeg = confinedArena.allocateFrom(C_POINTER, MemorySegment.NULL);
            withDataParamsSeg(paramBuffer, (paramsSeg) -> {
                try {
                    EVP_PKEY_FROMDATA_FUNC.invokeExact(this.evpPkeyCtx, evpPkeyPtrSeg, selection.mask, paramsSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
            });
            MemorySegment evpPkey = evpPkeyPtrSeg.get(C_POINTER, 0L);
            if (evpPkey.address() == 0L) {
                throw newOpenSslException("EVP_PKEY_fromdata: out pkey is NULL,");
            }
            return new EvpPkey(evpPkey, arena);
        }
    }

    @Override
    public void encapsulateInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_ENCAPSULATE_INIT_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    long[] encapsulate(MemorySegment wrappedKey, MemorySegment genKey) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment wrappedKeyLenSeg = arena.allocate(C_SIZE_T);
            MemorySegment genKeyLenSeg = arena.allocate(C_SIZE_T);

            // Not all KEM algorithm implementations in OpenSSL check that the genkey output
            // buffer is of sufficient size, so we retrieve the maximum output sizes for the
            // two output buffers here so that we can do the buffer size check prior to invoking
            // EVP_PKEY_encapsulate a second time to perform the encapsulate operation.
            try {
                // Retrieve max output sizes of wrapped key and gen key.
                EVP_PKEY_ENCAPSULATE_FUNC.invokeExact(this.evpPkeyCtx, MemorySegment.NULL, wrappedKeyLenSeg, MemorySegment.NULL, genKeyLenSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
            long wrappedKeyLen = wrappedKeyLenSeg.get(C_SIZE_T, 0L);
            long genKeyLen = genKeyLenSeg.get(C_SIZE_T, 0L);

            if (!wrappedKey.isNative() || wrappedKey.address() != 0L) {
                // Check buffer sizes.
                if (wrappedKeyLen > wrappedKey.byteSize()) {
                    throw new IndexOutOfBoundsException("wrappedKey output buffer is of insufficient size");
                }
                if (genKeyLen > genKey.byteSize()) {
                    throw new IndexOutOfBoundsException("genKey output buffer is of insufficient size");
                }

                MemorySegment wrappedKeySeg = toOffHeapSegment(wrappedKey.asSlice(0L, wrappedKeyLen), arena);
                MemorySegment genKeySeg = toOffHeapSegmentZeroize(genKey.asSlice(0L, genKeyLen), arena);
                try {
                    // Perform encapsulate operation.
                    EVP_PKEY_ENCAPSULATE_FUNC.invokeExact(this.evpPkeyCtx, wrappedKeySeg, wrappedKeyLenSeg, genKeySeg, genKeyLenSeg);
                } catch (Throwable t) {
                    throw mapException(t);
                }
                wrappedKeyLen = wrappedKeyLenSeg.get(C_SIZE_T, 0L);
                genKeyLen = genKeyLenSeg.get(C_SIZE_T, 0L);
                if (wrappedKeyLen > wrappedKeySeg.byteSize() || genKeyLen > genKeySeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }

                // Copy data back to Java heap, if necessary.
                if (!wrappedKey.isNative()) {
                    MemorySegment.copy(wrappedKeySeg, 0L, wrappedKey, 0L, wrappedKeyLen);
                }
                if (!genKey.isNative()) {
                    MemorySegment.copy(genKeySeg, 0L, genKey, 0L, genKeyLen);
                }
            }

            return new long[] {wrappedKeyLen, genKeyLen};
        }

    }

    @Override
    public int[] encapsulate(byte[] wrappedKey, int wrappedKeyOffset, byte[] genKey, int genKeyOffset) {
        MemorySegment wrappedKeySeg;
        MemorySegment genKeySeg;
        if (wrappedKey == null) {
            wrappedKeySeg = MemorySegment.NULL;
            genKeySeg = MemorySegment.NULL;
        } else {
            wrappedKeySeg = MemorySegment.ofArray(wrappedKey).asSlice(wrappedKeyOffset);
            genKeySeg = MemorySegment.ofArray(genKey).asSlice(genKeyOffset);
        }
        long[] lengths = encapsulate(wrappedKeySeg, genKeySeg);
        return new int[] {toIntExact(lengths[0]), toIntExact(lengths[1])};
    }

    @Override
    public void decapsulateInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_DECAPSULATE_INIT_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    long decapsulate(MemorySegment wrapped, MemorySegment unwrapped) {
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment unwrappedSeg = toOffHeapSegmentZeroize(unwrapped, arena);
            MemorySegment wrappedSeg = toOffHeapSegmentCopy(wrapped, arena);
            MemorySegment unwrappedLenSeg = arena.allocateFrom(C_SIZE_T, unwrappedSeg.byteSize());

            try {
                EVP_PKEY_DECAPSULATE_FUNC.invokeExact(this.evpPkeyCtx, unwrappedSeg, unwrappedLenSeg, wrappedSeg, wrappedSeg.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            long unwrappedLen = unwrappedLenSeg.get(C_SIZE_T, 0L);

            if (!unwrapped.isNative() || unwrapped.address() != 0L) {
                if (unwrappedLen > unwrappedSeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!unwrapped.isNative()) {
                    MemorySegment.copy(unwrappedSeg, 0L, unwrapped, 0L, unwrappedLen);
                }
            }

            return unwrappedLen;
        }
    }

    @Override
    public int decapsulate(byte[] wrapped, int wrappedOffset, int wrappedLen, byte[] unwrapped, int unwrappedOffset) {
        MemorySegment wrappedSeg = MemorySegment.ofArray(wrapped).asSlice(wrappedOffset, wrappedLen);
        MemorySegment unwrappedSeg = unwrapped == null ? MemorySegment.NULL : MemorySegment.ofArray(unwrapped).asSlice(unwrappedOffset);
        return toIntExact(decapsulate(wrappedSeg, unwrappedSeg));
    }

    @Override
    public void encryptInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_ENCRYPT_INIT_EX_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    long encrypt(MemorySegment in, MemorySegment out) {
        if (out.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment inSeg = toOffHeapSegmentCopyZeroize(in, arena);
            MemorySegment outSeg = toOffHeapSegment(out, arena);
            // out.byteSize() == 0L when out == MemorySegment.NULL
            MemorySegment outLenSeg = arena.allocateFrom(C_SIZE_T, out.byteSize());

            try {
                EVP_PKEY_ENCRYPT_FUNC.invokeExact(this.evpPkeyCtx, outSeg, outLenSeg, inSeg, inSeg.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            long outLen = outLenSeg.get(C_SIZE_T, 0L);

            if (!out.isNative() || out.address() != 0L) {
                if (outLen > outSeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!out.isNative()) {
                    MemorySegment.copy(outSeg, 0L, out, 0L, outLen);
                }
            }

            return outLen;
        }
    }

    @Override
    public int encrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        MemorySegment outSeg = out != null ? MemorySegment.ofArray(out).asSlice(outOffset) : MemorySegment.NULL;
        return toIntExact(encrypt(MemorySegment.ofArray(in).asSlice(inOffset, inLen), outSeg));
    }

    @Override
    public int encrypt(ByteBuffer in, ByteBuffer out) {
        MemorySegment outSeg = out != null ? MemorySegment.ofBuffer(out) : MemorySegment.NULL;
        int outLen = toIntExact(encrypt(MemorySegment.ofBuffer(in), outSeg));
        if (out != null) {
            in.position(in.limit());
            out.position(out.position() + outLen);
        }
        return outLen;
    }

    @Override
    public void decryptInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_DECRYPT_INIT_EX_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    long decrypt(MemorySegment in, MemorySegment out) {
        if (out.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment inSeg = toOffHeapSegmentCopy(in, arena);
            MemorySegment outSeg = toOffHeapSegmentZeroize(out, arena);
            // out.byteSize() == 0L when out == MemorySegment.NULL
            MemorySegment outLenSeg = arena.allocateFrom(C_SIZE_T, out.byteSize());

            try {
                EVP_PKEY_DECRYPT_FUNC.invokeExact(this.evpPkeyCtx, outSeg, outLenSeg, inSeg, inSeg.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            long outLen = outLenSeg.get(C_SIZE_T, 0L);

            if (!out.isNative() || out.address() != 0L) {
                if (outLen > outSeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!out.isNative()) {
                    MemorySegment.copy(outSeg, 0L, out, 0L, outLen);
                }
            }

            return outLen;
        }
    }

    @Override
    public int decrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) {
        MemorySegment outSeg = out != null ? MemorySegment.ofArray(out).asSlice(outOffset) : MemorySegment.NULL;
        return toIntExact(decrypt(MemorySegment.ofArray(in).asSlice(inOffset, inLen), outSeg));
    }

    @Override
    public int decrypt(ByteBuffer in, ByteBuffer out) {
        MemorySegment outSeg = out != null ? MemorySegment.ofBuffer(out) : MemorySegment.NULL;
        int outLen = toIntExact(decrypt(MemorySegment.ofBuffer(in), outSeg));
        if (out != null) {
            in.position(in.limit());
            out.position(out.position() + outLen);
        }
        return outLen;
    }

    @Override
    public void deriveInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_DERIVE_INIT_EX_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void deriveSetPeer(EVP_PKEY peer, boolean validatePeer) {
        try (Arena arena = Arena.ofConfined()) {
            try {
                EVP_PKEY_DERIVE_SET_PEER_EX_FUNC.invokeExact(this.evpPkeyCtx, ((EvpPkey) peer).upRefInternal(arena).evpPkey, validatePeer ? 1 : 0);
            } catch (Throwable t) {
                throw mapException(t);
            }
        }
    }

    long derive(MemorySegment key) {
        if (key.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment keySeg = toOffHeapSegmentZeroize(key, arena);
            // key.byteSize() == 0L when key == MemorySegment.NULL
            MemorySegment keyLenSeg = arena.allocateFrom(C_SIZE_T, key.byteSize());

            try {
                EVP_PKEY_DERIVE_FUNC.invokeExact(this.evpPkeyCtx, keySeg, keyLenSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
            long keyLen = keyLenSeg.get(C_SIZE_T, 0L);

            if (!key.isNative() || key.address() != 0L) {
                if (keyLen > keySeg.byteSize()) {
                    throw new AssertionError("Internal error: Buffer overrun");
                }
                if (!key.isNative()) {
                    MemorySegment.copy(keySeg, 0L, key, 0L, keyLen);
                }
            }

            return keyLen;
        }
    }

    @Override
    public int derive(byte[] key, int keyOffset) {
        MemorySegment keySeg = key != null ? MemorySegment.ofArray(key).asSlice(keyOffset) : MemorySegment.NULL;
        return toIntExact(derive(keySeg));
    }

    @Override
    public void keygenInit() {
        try {
            EVP_PKEY_KEYGEN_INIT_FUNC.invokeExact(this.evpPkeyCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void paramgenInit() {
        try {
            EVP_PKEY_PARAMGEN_INIT_FUNC.invokeExact(this.evpPkeyCtx);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public EVP_PKEY generate(OsslArena osslArena) {
        Arena arena = ((ArenaImpl) osslArena).arena;
        try (Arena confinedArena = Arena.ofConfined()) {
            MemorySegment evpPkeyPtrSeg = confinedArena.allocateFrom(C_POINTER, MemorySegment.NULL);
            try {
                EVP_PKEY_GENERATE_FUNC.invokeExact(this.evpPkeyCtx, evpPkeyPtrSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
            MemorySegment evpPkey = evpPkeyPtrSeg.get(C_POINTER, 0L);
            if (evpPkey.address() == 0L) {
                throw newOpenSslException("EVP_PKEY_generate: out pkey is NULL,");
            }
            return new EvpPkey(evpPkey, arena);
        }
    }

    @Override
    public void signInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_SIGN_INIT_EX_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void signMessageInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_SIGN_MESSAGE_INIT_FUNC.invokeExact(this.evpPkeyCtx, MemorySegment.NULL, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    long sign(MemorySegment tbs, MemorySegment sig) {
        if (sig.isReadOnly()) {
            throw new IllegalArgumentException("Output buffer is read-only");
        }
        try (Arena arena = Arena.ofConfined()) {
            MemorySegment tbsSeg = toOffHeapSegmentCopyZeroize(tbs, arena);
            MemorySegment sigSeg = toOffHeapSegment(sig, arena);
            // sig.byteSize() == 0L when sig == MemorySegment.NULL
            MemorySegment sigLenSeg = arena.allocateFrom(C_SIZE_T, sig.byteSize());

            try {
                EVP_PKEY_SIGN_FUNC.invokeExact(this.evpPkeyCtx, sigSeg, sigLenSeg, tbsSeg, tbsSeg.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            long sigLen = sigLenSeg.get(C_SIZE_T, 0L);

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
        MemorySegment sigSeg = sig != null ? MemorySegment.ofArray(sig).asSlice(sigOffset) : MemorySegment.NULL;
        return toIntExact(sign(MemorySegment.ofArray(tbs).asSlice(tbsOffset, tbsLen), sigSeg));
    }

    @Override
    public void verifyInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_VERIFY_INIT_EX_FUNC.invokeExact(this.evpPkeyCtx, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    @Override
    public void verifyMessageInit(OsslParamBuffer paramBuffer) {
        withDataParamsSeg(paramBuffer, (paramsSeg) -> {
            try {
                EVP_PKEY_VERIFY_MESSAGE_INIT_FUNC.invokeExact(this.evpPkeyCtx, MemorySegment.NULL, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }

    boolean verify(MemorySegment tbs, MemorySegment sig) throws SignatureException {
        try (Arena arena = Arena.ofConfined()) {
            int ret;
            MemorySegment tbsSeg = toOffHeapSegmentCopyZeroize(tbs, arena);
            MemorySegment sigSeg = toOffHeapSegmentCopy(sig, arena);
            try {
                ret = (int) EVP_PKEY_VERIFY_FUNC.invokeExact(this.evpPkeyCtx, sigSeg, sig.byteSize(), tbsSeg, tbsSeg.byteSize());
            } catch (Throwable t) {
                throw mapException(t);
            }
            if (ret != 1) {
                checkThrowSignatureVerifyException("EVP_PKEY_verify", ret);
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
