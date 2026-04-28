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

import java.io.Serial;

/**
 * General exception thrown when an error occurred in OpenSSL.
 */
public class OpenSslException extends RuntimeException {

    @Serial
    private static final long serialVersionUID = -8187293681832211822L;
    private final int errorCode;

    /**
     * Create OpenSslException with specified message.
     *
     * @param msg the message
     */
    public OpenSslException(String msg) {
        this(msg, null);
    }

    /**
     * Create OpenSslException with specified message and cause.
     *
     * @param msg the message
     * @param cause the cause, or <code>null</code> if the cause is nonexistent
     * or unknown.
     */
    public OpenSslException(String msg, Throwable cause) {
        this(msg, cause, 0);
    }

    /**
     * Create OpenSslException with specified message, cause, and error code.
     *
     * @param msg the message
     * @param cause the cause, or <code>null</code> if the cause is nonexistent
     * or unknown
     * @param errorCode the OpenSSL error code, or <code>0</code> if there is no error code
     */
    public OpenSslException(String msg, Throwable cause, int errorCode) {
        super(msg, cause);
        this.errorCode = errorCode;
    }

    /**
     * Returns the OpenSSL error code of the error that caused this exception to be thrown,
     * or  (zero) if the error was detected outside of OpenSSL or the OpenSSL
     * error code is not known.
     *
     * @return the OpenSSL error code, or <code>0</code> (zero)
     */
    public int errorCode() {
        return this.errorCode;
    }

    /**
     * Returns <code>true</code> if the error that caused this exception is an OpenSSL system error.
     *
     * @return <code>true</code> if the error is a system error, <code>false</code> otherwise
     */
    public boolean isSystemError() {
        return OpenSslErrorCode.isSystemError(this.errorCode);
    }

    /**
     * Returns the LIB field of the error code.
     *
     * @return the LIB field of the error code
     */
    public int getLib() {
        return OpenSslErrorCode.getLib(this.errorCode);
    }

    /**
     * Returns the RFLAGS field of the error code.
     *
     * @return the RFLAGS field of the error code
     */
    public int getRFlags() {
        return OpenSslErrorCode.getRFlags(this.errorCode);
    }

    /**
     * Returns the reason code of the error that caused this exception.
     *
     * @return the reason code component of the error code
     */
    public int getReason() {
        return OpenSslErrorCode.getReason(this.errorCode);
    }

    /**
     * Returns <code>true</code> if the error that caused this exception is a fatal error.
     *
     * @return <code>true</code> if the error is a fatal error, <code>false</code> otherwise
     */
    public boolean isFatalError() {
        return OpenSslErrorCode.isFatalError(this.errorCode);
    }

    /**
     * Returns <code>true</code> if the error that caused this exception is a common error.
     *
     * @return <code>true</code> if the error is a common error, <code>false</code> otherwise
     */
    public boolean isCommonError() {
        return OpenSslErrorCode.isCommonError(this.errorCode);
    }
}
