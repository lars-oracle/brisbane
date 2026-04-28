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

import java.security.SignatureException;

import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.EVP_R_PROVIDER_SIGNATURE_FAILURE;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.getReason;
import static com.oracle.jipher.internal.openssl.OpenSslErrorCode.isSystemError;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.clearErrorQueueInternal;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.newOpenSslException;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.peekErrorInternal;
import static com.oracle.jipher.internal.openssl.ffm.FfmOpenSsl.peekLastErrorInternal;

public class ErrorQueueUtil {
    private ErrorQueueUtil() {}  // Disallow object construction

    /**
     * Throws a SignatureException if the returnCode from a Signature Verify call
     * (EVP_PKEY_verify / EVP_DigestVerify[Final]), and the thread's error queue content,
     * indicate that a genuine error arose when attempting to verify the provided signature value.
     * If the error queue only contains a disregardable entry then the error queue is cleared.
     *
     * @param funcName the method (EVP_PKEY_verify / EVP_DigestVerify[Final]) call that produced the provided returnCode
     * @param ret the returnCode returned by the call to {@code funcName}
     *
     * @throws SignatureException if the returnCode from a Signature Verify call
     *         (EVP_PKEY_verify / EVP_DigestVerify[Final]), and the thread's error queue content
     *         indicate that a genuine error arose when attempting to verify the provided signature value.
     */
    static void checkThrowSignatureVerifyException(String funcName, int ret) throws SignatureException {
        boolean doThrow;
        if (ret == 0) {
            // From OpenSSL documentation: "zero indicates that the signature did not verify successfully ..."

            int errorCode = peekLastErrorInternal();
            if (errorCode == 0) {
                // The OpenSSL error queue is empty.
                doThrow = false;
            } else {
                // https://github.com/openssl/openssl/pull/27367 added the following to the implementation of
                // EVP_DigestSignFinal:
                //     if (!r) ERR_raise_data(ERR_LIB_EVP, EVP_R_PROVIDER_SIGNATURE_FAILURE, ...);
                // meaning R_PROVIDER_SIGNATURE_FAILURE will be present in the error queue when a signature did not
                // verify successfully even when no error occurred while attempting to verify the signature.
                //
                // Check if the error queue only contains an EVP_R_PROVIDER_SIGNATURE_FAILURE and avoid throwing
                // a SignatureException in that case.
                if (isSystemError(errorCode) || getReason(errorCode) != EVP_R_PROVIDER_SIGNATURE_FAILURE) {
                    // The OpenSSL error queue contains a system error or an error with a reason code other than
                    // EVP_R_PROVIDER_SIGNATURE_FAILURE.
                    doThrow = true;
                } else {
                    errorCode = peekErrorInternal();
                    if (isSystemError(errorCode) || getReason(errorCode) != EVP_R_PROVIDER_SIGNATURE_FAILURE) {
                        // The OpenSSL error queue contains a system error or an error with a reason code other than
                        // EVP_R_PROVIDER_SIGNATURE_FAILURE.
                        doThrow = true;
                    } else {
                        // The OpenSSL error queue only appears to contain an EVP_R_PROVIDER_SIGNATURE_FAILURE error.
                        // Clear the error queue.
                        clearErrorQueueInternal();
                        doThrow = false;
                    }
                }
            }
        } else {
            // ... "while other values indicate a more serious error (and sometimes also indicate an invalid signature form)."
            doThrow = true;
        }
        if (doThrow) {
            throw new SignatureException(newOpenSslException("%s (ret:%d)".formatted(funcName, ret)));
        }
    }

}
