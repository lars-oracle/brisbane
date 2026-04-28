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

public interface EVP_RAND extends OsslEvpAlgorithm {

    /* Known RAND names */
    String RAND_NAME_CTR_DRBG   = "CTR-DRBG";
    String RAND_NAME_HMAC_DRBG  = "HMAC-DRBG";
    String RAND_NAME_HASH_DRBG  = "HASH-DRBG";
    String RAND_NAME_CRNG_TEST  = "CRNG-TEST";
    String RAND_NAME_SEED_SRC   = "SEED-SRC";
    String RAND_NAME_JITTER     = "JITTER";
    String RAND_NAME_TEST_RAND  = "TEST-RAND";

    /* RAND / DRBG parameters */
    String RAND_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR;
    String RAND_PARAM_GENERATE              = "generate";
    String RAND_PARAM_MAX_REQUEST           = "max_request";
    String RAND_PARAM_STATE                 = "state";
    String RAND_PARAM_STRENGTH              = "strength";
    String RAND_PARAM_TEST_ENTROPY          = "test_entropy";
    String RAND_PARAM_TEST_NONCE            = "test_nonce";

    String DRBG_PARAM_CIPHER                = ALG_PARAM_CIPHER;
    String DRBG_PARAM_DIGEST                = ALG_PARAM_DIGEST;
    String DRBG_PARAM_FIPS_APPROVED_INDICATOR = ALG_PARAM_FIPS_APPROVED_INDICATOR;
    String DRBG_PARAM_FIPS_DIGEST_CHECK     = "digest-check";
    String DRBG_PARAM_MAC                   = ALG_PARAM_MAC;
    String DRBG_PARAM_MAX_ADINLEN           = "max_adinlen";
    String DRBG_PARAM_MAX_ENTROPYLEN        = "max_entropylen";
    String DRBG_PARAM_MAX_NONCELEN          = "max_noncelen";
    String DRBG_PARAM_MAX_PERSLEN           = "max_perslen";
    String DRBG_PARAM_MIN_ENTROPYLEN        = "min_entropylen";
    String DRBG_PARAM_MIN_NONCELEN          = "min_noncelen";
    String DRBG_PARAM_PROPERTIES            = ALG_PARAM_PROPERTIES;
    String DRBG_PARAM_RESEED_COUNTER        = "reseed_counter";
    String DRBG_PARAM_RESEED_REQUESTS       = "reseed_requests";
    String DRBG_PARAM_RESEED_TIME           = "reseed_time";
    String DRBG_PARAM_RESEED_TIME_INTERVAL  = "reseed_time_interval";
    String DRBG_PARAM_USE_DF                = "use_derivation_function";

    /* DRBG call-back parameters */
    String DRBG_PARAM_ENTROPY_REQUIRED      = "entropy_required";
    String DRBG_PARAM_MAX_LENGTH            = "maxium_length";
    String DRBG_PARAM_MIN_LENGTH            = "minium_length";
    String DRBG_PARAM_PREDICTION_RESISTANCE = "prediction_resistance";
    String DRBG_PARAM_RANDOM_DATA           = "random_data";
    String DRBG_PARAM_SIZE                  = "size";

    default EVP_RAND upRef() {
        return upRef(OsslArena.ofAuto());
    }
    EVP_RAND upRef(OsslArena arena);
}
