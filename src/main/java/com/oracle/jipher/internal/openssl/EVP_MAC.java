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

import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_CIPHER;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_DIGEST;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_FIPS_APPROVED_INDICATOR;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_PROPERTIES;

public interface EVP_MAC extends OsslEvpAlgorithm {

    /* The following are OpenSSL API mac constants defined in core_names.h */

    /* Known MAC names */
    String MAC_NAME_BLAKE2BMAC  = "BLAKE2BMAC";
    String MAC_NAME_BLAKE2SMAC  = "BLAKE2SMAC";
    String MAC_NAME_CMAC        = "CMAC";
    String MAC_NAME_GMAC        = "GMAC";
    String MAC_NAME_HMAC        = "HMAC";
    String MAC_NAME_KMAC128     = "KMAC128";
    String MAC_NAME_KMAC256     = "KMAC256";
    String MAC_NAME_POLY1305    = "POLY1305";
    String MAC_NAME_SIPHASH     = "SIPHASH";

    /* MAC parameters */
    String MAC_PARAM_BLOCK_SIZE     = "block-size";     /* size_t */
    String MAC_PARAM_C_ROUNDS       = "c-rounds";       /* unsigned int */
    String MAC_PARAM_CIPHER         = ALG_PARAM_CIPHER; /* utf8_string */
    String MAC_PARAM_CUSTOM         = "custom";         /* utf8_string */
    String MAC_PARAM_D_ROUNDS       = "d-rounds";       /* unsigned int */
    String MAC_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR; /* int, 0 or 1 */
    String MAC_PARAM_FIPS_KEY_CHECK = "key-check";      /* int, 0 or 1 */
    String MAC_PARAM_FIPS_NO_SHORT_MAC = "no-short-mac"; /* int, 0 or 1 */
    String MAC_PARAM_DIGEST         = ALG_PARAM_DIGEST; /* utf8_string */
    String MAC_PARAM_DIGEST_NOINIT  = "digest-noinit";  /* int, 0 or 1 */
    String MAC_PARAM_DIGEST_ONESHOT = "digest-oneshot"; /* int, 0 or 1 */
    String MAC_PARAM_IV             = "iv";             /* octet_string */
    String MAC_PARAM_KEY            = "key";            /* octet_string */
    String MAC_PARAM_PROPERTIES     = ALG_PARAM_PROPERTIES; /* utf8_string */
    String MAC_PARAM_SALT           = "salt";           /* octet_string */
    String MAC_PARAM_SIZE           = "size";           /* size_t */
    String MAC_PARAM_TLS_DATA_SIZE  = "tls-data-size";  /* size_t */
    String MAC_PARAM_XOF            = "xof";            /* int, 0 or 1 */

    default EVP_MAC upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_MAC upRef(OsslArena arena);
}
