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

import com.oracle.jipher.internal.openssl.OSSL_PROVIDER;
import com.oracle.jipher.internal.openssl.OsslParamBuffer;

import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.GET0_STRING_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.LinkerOption.CRITICAL;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.RETURN_CONST_PARAMS_FUNCDESC;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandle;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.downcallHandleCheckZeroNeg;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.mapException;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.newReadOnlyTemplateParamBuffer;
import static com.oracle.jipher.internal.openssl.ffm.OsslParamBufferImpl.withTemplateParamsSegIfNotEmpty;

final class OsslProvider implements OSSL_PROVIDER {

    static final MethodHandle OSSL_PROVIDER_GET0_NAME_FUNC;
    static final MethodHandle OSSL_PROVIDER_GETTABLE_PARAMS_FUNC;
    static final MethodHandle OSSL_PROVIDER_GET_PARAMS_FUNC;

    static {
        OSSL_PROVIDER_GET0_NAME_FUNC = downcallHandle(
                "OSSL_PROVIDER_get0_name", GET0_STRING_FUNCDESC, CRITICAL);
        OSSL_PROVIDER_GETTABLE_PARAMS_FUNC = downcallHandle(
                "OSSL_PROVIDER_gettable_params", RETURN_CONST_PARAMS_FUNCDESC, CRITICAL);
        OSSL_PROVIDER_GET_PARAMS_FUNC = downcallHandleCheckZeroNeg(
                "OSSL_PROVIDER_get_params", PARAMS_FUNCDESC);
    }

    final MemorySegment osslProvider;

    OsslProvider(MemorySegment osslProvider, Arena arena) {
        this.osslProvider = osslProvider.reinterpret(arena, null);
    }

    OsslProvider(MemorySegment osslProvider) {
        this.osslProvider = osslProvider;
    }

    @Override
    public String name() {
        try {
            MemorySegment nameSegment = (MemorySegment) OSSL_PROVIDER_GET0_NAME_FUNC.invokeExact(this.osslProvider);
            return nameSegment.getString(0L);
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public OsslParamBuffer gettableParams() {
        try {
            return newReadOnlyTemplateParamBuffer((MemorySegment) OSSL_PROVIDER_GETTABLE_PARAMS_FUNC.invokeExact(this.osslProvider));
        } catch (Throwable t) {
            throw mapException(t);
        }
    }

    @Override
    public void getParams(OsslParamBuffer paramBuffer) {
        withTemplateParamsSegIfNotEmpty(paramBuffer, (paramsSeg) -> {
            try {
                OSSL_PROVIDER_GET_PARAMS_FUNC.invokeExact(this.osslProvider, paramsSeg);
            } catch (Throwable t) {
                throw mapException(t);
            }
        });
    }
}
