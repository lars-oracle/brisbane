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

import java.util.Collections;
import java.util.HashMap;
import java.util.Map;

import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_ALGORITHM_ID;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_ALGORITHM_ID_PARAMS;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_FIPS_APPROVED_INDICATOR;

public interface EVP_CIPHER extends OsslEvpAlgorithm {

    /* The following are OpenSSL API cipher constants defined in evp.h or implementation defaults/limits defined in ciphercommon_gcm.h. */

    int MAX_BLOCK_LENGTH = 32;
    int MAX_IV_LENGTH = 16;
    int GCM_IV_DEFAULT_SIZE = 12;
    int GCM_IV_MAX_SIZE = 1024 / 8;
    int MAX_KEY_LENGTH = 64;

    /* Values for cipher flags */

    long CIPH_MODE                  = 0xF0007L;
    /* Set if variable length cipher */
    long CIPH_VARIABLE_LENGTH       = 0x8L;
    /* Set if the iv handling should be done by the cipher itself */
    long CIPH_CUSTOM_IV             = 0x10L;
    /* Set if the cipher's init() function should be called if key is NULL */
    long CIPH_ALWAYS_CALL_INIT      = 0x20L;
    /* Call ctrl() to init cipher parameters */
    long CIPH_CTRL_INIT             = 0x40L;
    /* Don't use standard key length function */
    long CIPH_CUSTOM_KEY_LENGTH     = 0x80L;
    /* Don't use standard block padding */
    long CIPH_NO_PADDING            = 0x100L;
    /* cipher handles random key generation */
    long CIPH_RAND_KEY              = 0x200L;
    /* cipher has its own additional copying logic */
    long CIPH_CUSTOM_COPY           = 0x400L;
    /* Don't use standard iv length function */
    long CIPH_CUSTOM_IV_LENGTH      = 0x800L;
    /* Buffer length in bits not bytes: CFB1 mode only */
    long CIPH_FLAG_LENGTH_BITS      = 0x2000L;

    /*
     * Cipher handles any and all padding logic as well as finalisation.
     */
    long CIPH_FLAG_CTS               = 0x4000L;
    long CIPH_FLAG_CUSTOM_CIPHER     = 0x100000L;
    long CIPH_FLAG_AEAD_CIPHER       = 0x200000L;
    long CIPH_FLAG_TLS1_1_MULTIBLOCK = 0x400000L;
    /* Cipher can handle pipeline operations */
    long CIPH_FLAG_PIPELINE          = 0x800000L;
    /* For provider implementations that handle ASN1 get/set param themselves */
    long CIPH_FLAG_CUSTOM_ASN1       = 0x1000000L;
    /* For ciphers generating unprotected CMS attributes */
    long CIPH_FLAG_CIPHER_WITH_MAC   = 0x2000000L;
    /* For supplementary wrap cipher support */
    long CIPH_FLAG_GET_WRAP_CIPHER   = 0x4000000L;
    long CIPH_FLAG_INVERSE_CIPHER    = 0x8000000L;

    /* The following are OpenSSL API cipher constants defined in core_names.h */

    /* cipher parameters */
    String CIPHER_PARAM_ALGORITHM_ID       = ALG_PARAM_ALGORITHM_ID; /* octet_string */
    String CIPHER_PARAM_ALGORITHM_ID_PARAMS = ALG_PARAM_ALGORITHM_ID_PARAMS; /* octet_string */
    String CIPHER_PARAM_BLOCK_SIZE         = "blocksize";   /* size_t */
    String CIPHER_PARAM_CTS                = "cts";         /* int, 0 or 1 */
    String CIPHER_PARAM_CTS_MODE           = "cts_mode";    /* utf8_string */
    String CIPHER_PARAM_CUSTOM_IV          = "custom-iv";   /* int, 0 or 1 */
    String CIPHER_PARAM_DECRYPT_ONLY       = "decrypt-only"; /* int, 0 or 1 */
    String CIPHER_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR; /* int, 0 or 1 */
    String CIPHER_PARAM_FIPS_ENCRYPT_CHECK = "encrypt-check"; /* int, 0 or 1 */
    String CIPHER_PARAM_HAS_RAND_KEY       = "has-randkey"; /* int, 0 or 1 */
    String CIPHER_PARAM_IV                 = "iv";          /* octet_string OR octet_ptr */
    String CIPHER_PARAM_IVLEN              = "ivlen";       /* size_t */
    String CIPHER_PARAM_KEYLEN             = "keylen";      /* size_t */
    String CIPHER_PARAM_MODE               = "mode";        /* uint */
    String CIPHER_PARAM_NUM                = "num";         /* uint */
    String CIPHER_PARAM_PADDING            = "padding";     /* uint */
    String CIPHER_PARAM_PIPELINE_AEAD_TAG  = "pipeline-tag"; /* octet_ptr */
    String CIPHER_PARAM_RANDOM_KEY         = "randkey";     /* octet_string */
    String CIPHER_PARAM_RC2_KEYBITS        = "keybits";     /* size_t */
    String CIPHER_PARAM_ROUNDS             = "rounds";      /* uint */
    String CIPHER_PARAM_SPEED              = "speed";       /* uint */
    String CIPHER_PARAM_TLS_MAC            = "tls-mac";     /* octet_ptr */
    String CIPHER_PARAM_TLS_MAC_SIZE       = "tls-mac-size"; /* size_t */
    String CIPHER_PARAM_TLS_VERSION        = "tls-version"; /* uint */
    String CIPHER_PARAM_TLS1_MULTIBLOCK    = "tls-multi";   /* int, 0 or 1 */
    String CIPHER_PARAM_UPDATED_IV         = "updated-iv";  /* octet_string OR octet_ptr */
    String CIPHER_PARAM_USE_BITS           = "use-bits";    /* uint */
    String OSSL_CIPHER_PARAM_XTS_STANDARD  = "xts_standard"; /* utf8_string */

    String CIPHER_PARAM_AEAD               = "aead";        /* int, 0 or 1 */
    String CIPHER_PARAM_AEAD_IV_GENERATED  = "iv-generated"; /* int, 0 or 1 */
    String CIPHER_PARAM_AEAD_IVLEN         = CIPHER_PARAM_IVLEN;
    String CIPHER_PARAM_AEAD_MAC_KEY       = "mackey";      /* octet_string */
    String CIPHER_PARAM_AEAD_TAG           = "tag";         /* octet_string */
    String CIPHER_PARAM_AEAD_TAGLEN        = "taglen";      /* size_t */
    String CIPHER_PARAM_AEAD_TLS1_AAD          = "tlsaad";      /* octet_string */
    String CIPHER_PARAM_AEAD_TLS1_AAD_PAD      = "tlsaadpad";   /* size_t */
    String CIPHER_PARAM_AEAD_TLS1_GET_IV_GEN   = "tlsivgen";    /* octet_string */
    String CIPHER_PARAM_AEAD_TLS1_IV_FIXED     = "tlsivfixed";  /* octet_string */
    String CIPHER_PARAM_AEAD_TLS1_SET_IV_INV   = "tlsivinv";    /* octet_string */

    String CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_SEND_FRAGMENT   = "tls1multi_maxsndfrag";   /* uint */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_MAX_BUFSIZE         = "tls1multi_maxbufsz";     /* size_t */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_INTERLEAVE          = "tls1multi_interleave";   /* uint */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_AAD                 = "tls1multi_aad";          /* octet_string */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_AAD_PACKLEN         = "tls1multi_aadpacklen";   /* uint */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_ENC                 = "tls1multi_enc";          /* octet_string */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_IN              = "tls1multi_encin";        /* octet_string */
    String CIPHER_PARAM_TLS1_MULTIBLOCK_ENC_LEN             = "tls1multi_enclen";       /* size_t */

    /* CIPHER_PARAM_CTS_MODE Values */
    String CIPHER_CTS_MODE_CS1 = "CS1";
    String CIPHER_CTS_MODE_CS2 = "CS2";
    String CIPHER_CTS_MODE_CS3 = "CS3";

    /* Cipher modes - as defined in evp.h */
    enum Mode {
        STREAM_CIPHER(0x0L),
        ECB(0x1L),
        CBC(0x2L),
        CFB(0x3L),
        OFB(0x4L),
        CTR(0x5L),
        GCM(0x6L),
        CCM(0x7L),
        XTS(0x10001L),
        WRAP(0x10002L),
        OCB(0x10003L),
        SIV(0x10004L);

        static final Map<Long,Mode> NUM_TO_MODE;
        static {
            Map<Long,Mode> numToMode = new HashMap<>();
            for (Mode mode : Mode.values()) {
                numToMode.put(mode.num, mode);
            }
            NUM_TO_MODE = Collections.unmodifiableMap(numToMode);
        }

        private final long num;

        public static Mode lookup(long num) {
            return NUM_TO_MODE.get(num);
        }

        Mode(long num) {
            this.num = num;
        }

        public long num() {
            return this.num;
        }
    }

    default EVP_CIPHER upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_CIPHER upRef(OsslArena arena);

    int blockSize();
    int keyLength();
    int ivLength();
    long flags();
    Mode mode();
}
