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

public interface EVP_MD extends OsslEvpAlgorithm {

    /* The following are OpenSSL API md constants defined in evp.h */

    int MAX_MD_SIZE = 64;

    /* The following are OpenSSL API md constants defined in core_names.h */

    /* Known DIGEST names (not a complete list) */
    String DIGEST_NAME_SHA1            = "SHA1";
    String DIGEST_NAME_SHA2_224        = "SHA2-224";
    String DIGEST_NAME_SHA2_256        = "SHA2-256";
    String DIGEST_NAME_SHA2_384        = "SHA2-384";
    String DIGEST_NAME_SHA2_512        = "SHA2-512";
    String DIGEST_NAME_SHA2_512_224    = "SHA2-512/224";
    String DIGEST_NAME_SHA2_512_256    = "SHA2-512/256";
    String DIGEST_NAME_SHA3_224        = "SHA3-224";
    String DIGEST_NAME_SHA3_256        = "SHA3-256";
    String DIGEST_NAME_SHA3_384        = "SHA3-384";
    String DIGEST_NAME_SHA3_512        = "SHA3-512";
    String DIGEST_NAME_KECCAK_KMAC128  = "KECCAK-KMAC-128";
    String DIGEST_NAME_KECCAK_KMAC256  = "KECCAK-KMAC-256";

    /* digest parameters */
    String DIGEST_PARAM_XOFLEN         = "xoflen";        /* size_t */
    String DIGEST_PARAM_SSL3_MS        = "ssl3-ms";       /* octet_string */
    String DIGEST_PARAM_PAD_TYPE       = "pad-type";      /* uint */
    String DIGEST_PARAM_MICALG         = "micalg";        /* utf8_string */
    String DIGEST_PARAM_BLOCK_SIZE     = "blocksize";     /* size_t */
    String DIGEST_PARAM_SIZE           = "size";          /* size_t */
    String DIGEST_PARAM_XOF            = "xof";           /* int, 0 or 1 */
    String DIGEST_PARAM_ALGID_ABSENT   = "algid-absent";  /* int, 0 or 1 */

    default EVP_MD upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_MD upRef(OsslArena arena);

    int blockSize();
    int size();
}
