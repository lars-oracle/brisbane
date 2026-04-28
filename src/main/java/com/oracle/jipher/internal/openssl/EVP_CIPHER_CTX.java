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
import javax.crypto.ShortBufferException;

public interface EVP_CIPHER_CTX extends OsslSetParams, Poolable {

    enum Enc {
        NO_CHANGE, DECRYPTION, ENCRYPTION
    }

    EVP_CIPHER_CTX dup(OsslArena arena);
    EVP_CIPHER_CTX dup();

    void reset();
    boolean isInitialized();

    int blockSize();
    int keyLength();
    int ivLength();
    int tagLength();
    void init(EVP_CIPHER type, byte[] key, byte[] iv, Enc enc, OsslParamBuffer paramBuffer);
    default void init(EVP_CIPHER type, byte[] key, byte[] iv, Enc enc, OSSL_PARAM... params) {
        init(type, key, iv, enc, OpenSsl.getInstance().dataParamBuffer(params));
    }
    boolean isEncrypting();
    int update(ByteBuffer in, ByteBuffer out) throws ShortBufferException;
    int update(byte[] in, int inOffset, int inLen, byte[] out, int outOffset) throws ShortBufferException;
    int doFinal(ByteBuffer out) throws ShortBufferException;
    int doFinal(byte[] out, int outOffset) throws ShortBufferException;
}
