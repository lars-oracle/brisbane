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

package com.oracle.jipher.internal.fips;

import com.oracle.jipher.internal.common.Debug;
import com.oracle.jipher.internal.common.ToolkitProperties;
import com.oracle.jipher.internal.openssl.MdAlg;

import static com.oracle.jipher.internal.fips.CryptoOp.DECRYPT_ASYM;
import static com.oracle.jipher.internal.fips.CryptoOp.DECRYPT_SYM;
import static com.oracle.jipher.internal.fips.CryptoOp.ENCRYPT_ASYM;
import static com.oracle.jipher.internal.fips.CryptoOp.ENCRYPT_SYM;
import static com.oracle.jipher.internal.fips.CryptoOp.KEYAGREE;
import static com.oracle.jipher.internal.fips.CryptoOp.KEYDERIVE;
import static com.oracle.jipher.internal.fips.CryptoOp.KEYGEN;
import static com.oracle.jipher.internal.fips.CryptoOp.MAC;
import static com.oracle.jipher.internal.fips.CryptoOp.SIGN;
import static com.oracle.jipher.internal.fips.CryptoOp.VERIFY;

/**
 * Class for obtaining FIPS enforcement policy impl.
 * <p>
 * Three policies are supported:
 * - FIPS - (default) enforces according to the 'Acceptable' and 'Legacy use' guidelines as defined in SP 800-131A Rev. 2
 * - FIPS_STRICT - enforces according to the 'Acceptable' use guidelines ONLY as defined in SP 800-131A Rev. 2.
 *                 It does not permit "Legacy use" .
 * - NONE - No enforcement is applied by the bytecode. Note: The OpenSSL FIPS provider still enforces FIPS restrictions
 */
public class Fips {

    /**
     * An enum representing FIPS enforcement policies
     */
    public enum EnforcementPolicy {
        FIPS, // Permits 'Acceptable' and 'Legacy use' as defined in SP 800-131A Rev. 2.
        FIPS_STRICT, // Permits 'Acceptable' use ONLY as defined in SP 800-131A Rev. 2.  Does not allow 'Legacy use'.
        NONE, // No enforcement is applied by the bytecode.
              // Note: The OpenSSL FIPS provider still enforces FIPS restrictions.
    }

    private Fips() {
        // Prevent instantiation
    }

    static final Debug DEBUG = Debug.getInstance("jipher");


    private static final Policy ENFORCER = initPolicy();

    /**
     * Get the toolkit enforcement policy.
     * @return the policy configured for the toolkit
     */
    public static Policy enforcement() {
        return ENFORCER;
    }

    private static Policy initPolicy() {
        Policy policy = switch (ToolkitProperties.getFipsEnforcementValue()) {
            case NONE -> none();
            case FIPS_STRICT -> fipsStrictPolicy();
            default -> fipsPolicy();
        };
        DEBUG.println("Setting FIPS enforcement policy = " + policy.getPolicyName());
        return policy;
    }

    /**
     * Create the FIPS_STRICT policy. This policy defines rules according to the 'Acceptable' use guidelines only
     * as defined in SP 800-131A Rev. 2. It does not permit 'Legacy use' .
     *
     * @return the created Policy
     */
    static Policy fipsStrictPolicy() {
        // JCA Service algorithms that use DESede or DSA keys are not registered when the policy is POLICY_FIPS_STRICT
        // Consequently, policy rules for these key types are not required when the policy is POLICY_FIPS_STRICT.
        return new Policy.Builder(EnforcementPolicy.FIPS_STRICT.name())
                .strengthRule("RSA", (keyBits) -> (int) keyBits >= 2048, ENCRYPT_ASYM, DECRYPT_ASYM, KEYGEN, SIGN, VERIFY) // SP 800-131A Rev. 2 Table 2, Acceptable
                .strengthRule("EC", (curveBits) -> (int) curveBits >= 224, KEYGEN, SIGN, VERIFY, KEYAGREE) // SP 800-131A Rev. 2 Table 2, Acceptable
                .strengthRule("DH", (keyBits) -> (int) keyBits >= 2048, KEYAGREE, KEYGEN)
                .strengthRule("HMAC", (keyBits) -> (int) keyBits >= 112, MAC) // SP 800-131A Rev. 2 Table 9 HMAC, Acceptable
                .strengthRule("KDF",  (keyBits) -> (int) keyBits >= 112, KEYGEN, KEYDERIVE) // SP 800-131A Rev. 2 Section 8
                .strengthRule("AES", (keyBits) -> (int) keyBits >= 128, ENCRYPT_SYM, DECRYPT_SYM) // SP 800-131A Rev. 2 Table 1, Acceptable
                // The following SHA1 rule is applicable to RSASSA-PSS signatures that use a SHA1 digest algorithm parameter.
                .algRule((mdAlg) -> !MdAlg.SHA1.getAlg().equals(mdAlg), SIGN, VERIFY) // SP 800-131A Rev. 2 Table 8, Acceptable.
                .build();
    }

    /**
     * Create the FIPS policy. This policy defines rules according to the 'Acceptable' and 'Legacy use' guidelines
     * as defined in  SP 800-131A Rev. 2. This is the default.
     *
     * @return the created Policy
     */
    static Policy fipsPolicy() {
        return new Policy.Builder(EnforcementPolicy.FIPS.name())
                .keyTypeRule((keyType) -> !((String) keyType).equalsIgnoreCase("DSA"), SIGN) // FIPS 140-3 IG, section C.K Legacy Use
                .strengthRule("RSA", (keyBits) -> (int) keyBits >= 2048, ENCRYPT_ASYM, DECRYPT_ASYM, KEYGEN, SIGN) // SP 800-131A Rev. 2 Table 2, Acceptable
                .strengthRule("RSA", (keyBits) -> (int) keyBits >= 1024, VERIFY) // SP 800-131A Rev. 2 Table 2, Legacy use
                .strengthRule("EC", (curveBits) -> (int) curveBits >= 224, KEYGEN, SIGN, KEYAGREE) // SP 800-131A Rev. 2 Table 2, Acceptable
                .strengthRule("EC", (curveBits) -> (int) curveBits >= 160, VERIFY) // SP 800-131A Rev. 2 Table 2, Legacy use
                .strengthRule("DSA", (paramBits) -> ((int[]) paramBits)[0] >= 512, VERIFY) // SP 800-131A Rev. 2 Table 2, Legacy use
                .strengthRule("DH", (keyBits) -> (int) keyBits >= 2048, KEYAGREE, KEYGEN)
                .strengthRule("HMAC", (keyBits) -> (int) keyBits >= 0, MAC) // SP 800-131A Rev. 2 Table 9 HMAC Verification, Legacy use
                .strengthRule("KDF",  (keyBits) -> (int) keyBits >= 112, KEYGEN, KEYDERIVE) // SP 800-131A Rev. 2 Section 8
                .strengthRule("AES", (keyBits) -> (int) keyBits >= 128, ENCRYPT_SYM, DECRYPT_SYM)  // SP 800-131A Rev. 2 Table 1, Acceptable
                .strengthRule("DESede", (keyBits) -> (int) keyBits == 192, ENCRYPT_SYM, DECRYPT_SYM) // SP 800-131A Rev. 2 Table 1, Legacy use
                .algRule((mdAlg) -> !MdAlg.SHA1.getAlg().equals(mdAlg), SIGN)  // SP 800-131A Rev. 2 Table 8, Legacy use
                .algRule((cipherAlg) -> !((String) cipherAlg).contains("DESede"), ENCRYPT_SYM) // SP 800-131A Rev. 2 Table 1, Legacy use
                .build();
    }

    /**
     * Create a policy which enforces nothing.
     *
     * @return the created Policy
     */
    static Policy none() {
        return new Policy.Builder(EnforcementPolicy.NONE.name()).build();
    }

}


