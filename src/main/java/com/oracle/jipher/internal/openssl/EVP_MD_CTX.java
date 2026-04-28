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

import java.nio.ByteBuffer;
import java.security.SignatureException;
import java.util.function.Consumer;

public interface EVP_MD_CTX extends OsslSetParams, Poolable {

    EVP_MD_CTX dup(OsslArena arena);
    EVP_MD_CTX dup();

    void reset();
    boolean isInitialized();

    int blockSize();
    int size();
    void init(EVP_MD type, OsslParamBuffer paramBuffer);
    default void init(EVP_MD type, OSSL_PARAM... params) {
        init(type, OpenSsl.getInstance().dataParamBuffer(params));
    }
    void update(ByteBuffer in);
    void update(byte[] in, int inOffset, int inLen);
    int digestFinal(byte[] out, int outOffset);

    void signInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OsslParamBuffer paramBuffer);
    default void signInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OSSL_PARAM... params) {
        signInit(evpPkeyCtxConsumer, mdName, libCtx, properties, pkey, OpenSsl.getInstance().dataParamBuffer(params));
    }
    void signUpdate(byte[] data, int dataOffset, int dataLen);
    void signUpdate(ByteBuffer data);
    int signFinal(byte[] sig, int sigOffset);
    int sign(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset);
    void verifyInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OsslParamBuffer paramBuffer);
    default void verifyInit(Consumer<EVP_PKEY_CTX> evpPkeyCtxConsumer, String mdName, OSSL_LIB_CTX libCtx, String properties, EVP_PKEY pkey, OSSL_PARAM... params) {
        verifyInit(evpPkeyCtxConsumer, mdName, libCtx, properties, pkey, OpenSsl.getInstance().dataParamBuffer(params));
    }
    void verifyUpdate(byte[] data, int dataOffset, int dataLen);
    void verifyUpdate(ByteBuffer data);
    boolean verifyFinal(byte[] sig, int sigOffset, int sigLen) throws SignatureException;
    boolean verify(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset, int sigLen) throws SignatureException;
}
