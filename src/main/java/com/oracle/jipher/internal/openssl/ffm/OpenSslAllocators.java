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

import com.oracle.jipher.internal.openssl.OpenSslException;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.constString;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckNull;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;

final class OpenSslAllocators {

    static final long MIN_ALLOCATION = 1L;

    static final MethodHandle MALLOC_FUNC;
    static final MethodHandle ZALLOC_FUNC;
    static final MethodHandle FREE_FUNC;
    static final MethodHandle CLEAR_FREE_FUNC;

    static final MemorySegment FILE_STRING;

    static {
        MALLOC_FUNC = downcallHandleCheckNull(
                "CRYPTO_malloc", "(SMI)M");
        ZALLOC_FUNC = downcallHandleCheckNull(
                "CRYPTO_zalloc", "(SMI)M");
        FREE_FUNC = downcallHandle(
                "CRYPTO_free", "(MMI)V");
        CLEAR_FREE_FUNC = downcallHandle(
                "CRYPTO_clear_free", "(MSMI)V");

        FILE_STRING = constString(OpenSslAllocators.class.getName());
    }

    static MemorySegment malloc(long byteSize, Arena arena) {
        MemorySegment segment = malloc(byteSize);
        return segment.reinterpret(byteSize, arena, OpenSslAllocators::free);
    }

    static MemorySegment mallocClearFree(long byteSize, Arena arena) {
        MemorySegment segment = malloc(byteSize);
        return segment.reinterpret(byteSize, arena, (seg) -> clearFree(seg, byteSize));
    }

    static MemorySegment zallocClearFree(long byteSize, Arena arena) {
        MemorySegment segment = zalloc(byteSize);
        return segment.reinterpret(byteSize, arena, (seg) -> clearFree(seg, byteSize));
    }

    static MemorySegment malloc(long byteSize) {
        try {
            return (MemorySegment) MALLOC_FUNC.invokeExact(Math.max(byteSize, MIN_ALLOCATION), FILE_STRING, 0);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static MemorySegment zalloc(long byteSize) {
        try {
            return (MemorySegment) ZALLOC_FUNC.invokeExact(Math.max(byteSize, MIN_ALLOCATION), FILE_STRING, 0);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static void free(MemorySegment seg) {
        try {
            FREE_FUNC.invokeExact(seg, FILE_STRING, 0);
        } catch (OpenSslException e) {
            throw e;
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    static void clearFree(MemorySegment seg, long len) {
        try {
            CLEAR_FREE_FUNC.invokeExact(seg, len, FILE_STRING, 0);
        } catch (OpenSslException e) {
            throw e;
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

}
