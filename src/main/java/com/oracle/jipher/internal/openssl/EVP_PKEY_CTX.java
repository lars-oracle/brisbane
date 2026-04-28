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

import com.oracle.jipher.internal.openssl.EVP_PKEY.Selection;

public interface EVP_PKEY_CTX extends OsslSetParams {

    default EVP_PKEY_CTX dup() {
        return dup(OsslArena.ofAuto());
    }
    EVP_PKEY_CTX dup(OsslArena arena);

    boolean isA(String keyType);

    OsslParamBuffer fromdataSettableParams(Selection selection);
    void fromdataInit();
    EVP_PKEY fromdata(Selection selection, OsslArena osslArena, OsslParamBuffer paramBuffer);
    default EVP_PKEY fromdata(Selection selection, OsslParamBuffer paramBuffer) {
        return fromdata(selection, OsslArena.ofAuto(), paramBuffer);
    }
    default EVP_PKEY fromdata(Selection selection, OsslArena osslArena, OSSL_PARAM... params) {
        return fromdata(selection, osslArena, OpenSsl.getInstance().dataParamBuffer(params));
    }
    default EVP_PKEY fromdata(Selection selection, OSSL_PARAM... params) {
        return fromdata(selection, OsslArena.ofAuto(), params);
    }

    void encryptInit(OsslParamBuffer paramBuffer);
    default void encryptInit(OSSL_PARAM... params) {
        encryptInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    int encrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset);
    int encrypt(ByteBuffer in, ByteBuffer out);
    void decryptInit(OsslParamBuffer paramBuffer);
    default void decryptInit(OSSL_PARAM... params) {
        decryptInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    int decrypt(byte[] in, int inOffset, int inLen, byte[] out, int outOffset);
    int decrypt(ByteBuffer in, ByteBuffer out);

    void encapsulateInit(OsslParamBuffer paramBuffer);
    default void encapsulateInit(OSSL_PARAM... params) {
        encapsulateInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    int[] encapsulate(byte[] wrappedKey, int wrappedKeyOffset, byte[] genKey, int genKeyOffset);

    void decapsulateInit(OsslParamBuffer paramBuffer);
    default void decapsulateInit(OSSL_PARAM... params) {
        decapsulateInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    int decapsulate(byte[] wrapped, int wrappedOffset, int wrappedLen, byte[] unwrapped, int unwrappedOffset);

    void deriveInit(OsslParamBuffer paramBuffer);
    default void deriveInit(OSSL_PARAM... params) {
        deriveInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    void deriveSetPeer(EVP_PKEY peer, boolean validatePeer);
    default void deriveSetPeer(EVP_PKEY peer) {
        deriveSetPeer(peer, true);
    }
    int derive(byte[] key, int keyOffset);

    void keygenInit();
    void paramgenInit();
    EVP_PKEY generate(OsslArena osslArena);
    default EVP_PKEY generate() {
        return generate(OsslArena.ofAuto());
    }

    void signInit(OsslParamBuffer paramBuffer);
    default void signInit(OSSL_PARAM... params) {
        signInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    void signMessageInit(OsslParamBuffer paramBuffer);
    default void signMessageInit(OSSL_PARAM... params) {
        signMessageInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    int sign(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset);
    void verifyInit(OsslParamBuffer paramBuffer);
    default void verifyInit(OSSL_PARAM... params) {
        verifyInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    void verifyMessageInit(OsslParamBuffer paramBuffer);
    default void verifyMessageInit(OSSL_PARAM... params) {
        verifyMessageInit(OpenSsl.getInstance().dataParamBuffer(params));
    }
    boolean verify(byte[] tbs, int tbsOffset, int tbsLen, byte[] sig, int sigOffset, int sigLen) throws SignatureException;
}
