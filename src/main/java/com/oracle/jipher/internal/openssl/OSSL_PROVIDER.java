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

public interface OSSL_PROVIDER extends OsslGetParams {

    /* The following are OpenSSL API constants, defined in core_names.h, that identify parameters Providers can define. */
    String PROV_PARAM_NAME                       = "name";                       /* utf8_ptr */
    String PROV_PARAM_VERSION                    = "version";                    /* utf8_ptr */
    String PROV_PARAM_BUILDINFO                  = "buildinfo";                  /* utf8_ptr */
    String PROV_PARAM_STATUS                     = "status";                     /* uint */
    String PROV_PARAM_SECURITY_CHECKS            = "security-checks";            /* uint */
    String PROV_PARAM_TLS1_PRF_EMS_CHECK         = "tls1-prf-ems-check";         /* uint */
    String PROV_PARAM_NO_SHORT_MAC               = "no-short-mac";               /* uint */
    String PROV_PARAM_HMAC_KEY_CHECK             = "hmac-key-check";             /* uint */
    String PROV_PARAM_KMAC_KEY_CHECK             = "kmac-key-check";             /* uint */
    String PROV_PARAM_DRBG_TRUNC_DIGEST          = "drbg-no-trunc-md";           /* uint */
    String PROV_PARAM_SIGNATURE_DIGEST_CHECK     = "signature-digest-check";     /* uint */
    String PROV_PARAM_HKDF_DIGEST_CHECK          = "hkdf-digest-check";          /* uint */
    String PROV_PARAM_TLS13_KDF_DIGEST_CHECK     = "tls13-kdf-digest-check";     /* uint */
    String PROV_PARAM_TLS1_PRF_DIGEST_CHECK      = "tls1-prf-digest-check";      /* uint */
    String PROV_PARAM_SSHKDF_DIGEST_CHECK        = "sshkdf-digest-check";        /* uint */
    String PROV_PARAM_SSKDF_DIGEST_CHECK         = "sskdf-digest-check";         /* uint */
    String PROV_PARAM_X963KDF_DIGEST_CHECK       = "x963kdf-digest-check";       /* uint */
    String PROV_PARAM_DSA_SIGN_DISABLED          = "dsa-sign-disabled";          /* uint */
    String PROV_PARAM_TDES_ENCRYPT_DISABLED      = "tdes-encrypt-disabled";      /* uint */
    String PROV_PARAM_RSA_PKCS15_PAD_DISABLED    = "rsa-pkcs15-pad-disabled";    /* uint */
    String PROV_PARAM_RSA_PSS_SALTLEN_CHECK      = "rsa-pss-saltlen-check";      /* uint */
    String PROV_PARAM_RSA_SIGN_X931_PAD_DISABLED = "rsa-sign-x931-pad-disabled"; /* uint */
    String PROV_PARAM_HKDF_KEY_CHECK             = "hkdf-key-check";             /* uint */
    String PROV_PARAM_KBKDF_KEY_CHECK            = "kbkdf-key-check";            /* uint */
    String PROV_PARAM_TLS13_KDF_KEY_CHECK        = "tls13-kdf-key-check";        /* uint */
    String PROV_PARAM_TLS1_PRF_KEY_CHECK         = "tls1-prf-key-check";         /* uint */
    String PROV_PARAM_SSHKDF_KEY_CHECK           = "sshkdf-key-check";           /* uint */
    String PROV_PARAM_SSKDF_KEY_CHECK            = "sskdf-key-check";            /* uint */
    String PROV_PARAM_X963KDF_KEY_CHECK          = "x963kdf-key-check";          /* uint */
    String PROV_PARAM_X942KDF_KEY_CHECK          = "x942kdf-key-check";          /* uint */
    String PROV_PARAM_PBKDF2_LOWER_BOUND_CHECK   = "pbkdf2-lower-bound-check";   /* uint */
    String PROV_PARAM_ECDH_COFACTOR_CHECK        = "ecdh-cofactor-check";        /* uint */

    String name();
}
