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
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_MAC;
import static com.oracle.jipher.internal.openssl.OSSL_PARAM.ALG_PARAM_PROPERTIES;

public interface EVP_KDF extends OsslEvpAlgorithm {

    /* The following are OpenSSL API kdf constants defined in core_names.h */

    /* Known KDF names */
    String KDF_NAME_HKDF            = "HKDF";
    String KDF_NAME_TLS1_3_KDF      = "TLS13-KDF";
    String KDF_NAME_PBKDF1          = "PBKDF1";
    String KDF_NAME_PBKDF2          = "PBKDF2";
    String KDF_NAME_SCRYPT          = "SCRYPT";
    String KDF_NAME_PKCS12          = "PKCS12KDF";
    String KDF_NAME_SSHKDF          = "SSHKDF";
    String KDF_NAME_SSKDF           = "SSKDF";
    String KDF_NAME_TLS1_PRF        = "TLS1-PRF";
    String KDF_NAME_X942KDF_ASN1    = "X942KDF-ASN1";
    String KDF_NAME_X942KDF_CONCAT  = "X942KDF-CONCAT";
    String KDF_NAME_X963KDF         = "X963KDF";
    String KDF_NAME_KBKDF           = "KBKDF";
    String KDF_NAME_KRB5KDF         = "KRB5KDF";
    String KDF_NAME_HMACDRBGKDF     = "HMAC-DRBG-KDF";


    /* KDF / PRF parameters */
    String KDF_PARAM_ARGON2_AD          = "ad";         /* octet_string */
    String KDF_PARAM_ARGON2_LANES       = "lanes";      /* uint */
    String KDF_PARAM_ARGON2_MEMCOST     = "memcost";    /* uint */
    String KDF_PARAM_ARGON2_VERSION     = "version";    /* uint */
    String KDF_PARAM_CEK_ALG            = "cekalg";     /* utf8_string */
    String KDF_PARAM_CIPHER             = ALG_PARAM_CIPHER; /* utf8_string */
    String KDF_PARAM_CONSTANT           = "constant";   /* octet_string */
    String KDF_PARAM_DATA               = "data";       /* octet_string */
    String KDF_PARAM_DIGEST             = ALG_PARAM_DIGEST; /* utf8_string */
    String KDF_PARAM_EARLY_CLEAN        = "early_clean"; /* uint */
    String KDF_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR; /* int, 0 or 1 */
    String KDF_PARAM_FIPS_DIGEST_CHECK  = "digest-check"; /* int, 0 or 1 */
    String KDF_PARAM_FIPS_EMS_CHECK     = "ems_check";  /* int, 0 or 1 */
    String KDF_PARAM_FIPS_KEY_CHECK     = "key-check";  /* int, 0 or 1 */
    String KDF_PARAM_HMACDRBG_ENTROPY   = "entropy";    /* octet_string */
    String KDF_PARAM_HMACDRBG_NONCE     = "nonce";      /* octet_string */
    String KDF_PARAM_INFO               = "info";       /* octet_string */
    String KDF_PARAM_ITER               = "iter";       /* uint */
    String KDF_PARAM_KBKDF_R            = "r";          /* int */
    String KDF_PARAM_KBKDF_USE_L        = "use-l";      /* int */
    String KDF_PARAM_KBKDF_USE_SEPARATOR = "use-separator"; /* int */
    String KDF_PARAM_KEY                = "key";        /* octet_string */
    String KDF_PARAM_LABEL              = "label";      /* octet_string */
    String KDF_PARAM_MAC                = ALG_PARAM_MAC; /* utf8_string */
    String KDF_PARAM_MAC_SIZE           = "maclen";     /* size_t */
    String KDF_PARAM_MODE               = "mode";       /* utf8_string or int */
    String KDF_PARAM_PASSWORD           = "pass";       /* octet_string */
    String KDF_PARAM_PKCS12_ID          = "id";         /* int */
    String KDF_PARAM_PKCS5              = "pkcs5";      /* int */
    String KDF_PARAM_PREFIX             = "prefix";     /* octet_string */
    String KDF_PARAM_PROPERTIES         = ALG_PARAM_PROPERTIES; /* utf8_string */
    String KDF_PARAM_SALT               = "salt";       /* octet_string */
    String KDF_PARAM_SCRYPT_MAXMEM      = "maxmem_bytes"; /* uint64_t */
    String KDF_PARAM_SCRYPT_N           = "n";          /* uint64_t */
    String KDF_PARAM_SCRYPT_P           = "p";          /* uint32_t */
    String KDF_PARAM_SCRYPT_R           = "r";          /* uint32_t */
    String KDF_PARAM_SECRET             = "secret";     /* octet_string */
    String KDF_PARAM_SEED               = "seed";       /* octet_string */
    String KDF_PARAM_SIZE               = "size";       /* size_t */
    String KDF_PARAM_SSHKDF_SESSION_ID  = "session_id"; /* octet_string */
    String KDF_PARAM_SSHKDF_TYPE        = "type";       /* int */
    String KDF_PARAM_SSHKDF_XCGHASH     = "xcghash";    /* octet_string */
    String KDF_PARAM_THREADS            = "threads";    /* uint */
    String KDF_PARAM_UKM                = "ukm";        /* octet_string */
    String KDF_PARAM_X942_ACVPINFO      = "acvp-info";
    String KDF_PARAM_X942_PARTYUINFO    = "partyu-info";
    String KDF_PARAM_X942_PARTYVINFO    = "partyv-info";
    String KDF_PARAM_X942_SUPP_PRIVINFO = "supp-privinfo";
    String KDF_PARAM_X942_SUPP_PUBINFO  = "supp-pubinfo";
    String KDF_PARAM_X942_USE_KEYBITS   = "use-keybits";

    default EVP_KDF upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_KDF upRef(OsslArena arena);
}
