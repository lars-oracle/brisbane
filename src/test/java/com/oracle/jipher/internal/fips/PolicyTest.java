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

import java.math.BigInteger;
import java.security.Key;
import java.security.ProviderException;
import java.security.interfaces.ECPublicKey;
import java.security.interfaces.RSAPublicKey;
import java.security.spec.ECParameterSpec;
import java.util.Arrays;
import javax.crypto.interfaces.DHPrivateKey;
import javax.crypto.spec.DHParameterSpec;

import org.junit.Test;

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
import static org.junit.Assert.assertEquals;
import static org.junit.Assert.fail;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.when;

public class PolicyTest {

    @Test
    public void test() throws Exception {
        Policy pol = new Policy.Builder("NAME").build();
        assertEquals("NAME", pol.getPolicyName());
        for (CryptoOp op : CryptoOp.values()) {
            pol.checkStrength(op, "DUMMY ALGORITHM", 23);
            pol.checkAlg(op, "DUMMY ALGORITHM");
        }
    }

    @Test
    public void checkStrengthKeyRSA() {
        RSAPublicKey rsaKey = mock(RSAPublicKey.class);
        BigInteger mod = mock(BigInteger.class);
        when(mod.bitLength()).thenReturn(1234);
        when(rsaKey.getModulus()).thenReturn(mod);

        int[] chk = new int[1];
        Policy pol = new Policy.Builder("NAME")
                .strengthRule("RSA", i -> { chk[0] = (int) i; return true; }, KEYGEN)
                .build();
        pol.checkStrength(KEYGEN, rsaKey);
        assertEquals(1234, chk[0]);
    }

    @Test
    public void checkStrengthKeyEC() {
        ECPublicKey ecKey = mock(ECPublicKey.class);
        ECParameterSpec params = mock(ECParameterSpec.class);
        BigInteger order = mock(BigInteger.class);
        when(order.bitLength()).thenReturn(999);
        when(ecKey.getParams()).thenReturn(params);
        when(params.getOrder()).thenReturn(order);

        int[] chk = new int[1];
        Policy pol = new Policy.Builder("NAME")
                .strengthRule("EC", i -> { chk[0] = (int) i; return true; }, KEYGEN)
                .build();
        pol.checkStrength(KEYGEN, ecKey);
        assertEquals(999, chk[0]);
    }

    @Test
    public void checkStrengthKeyDH() {
        DHPrivateKey dhKey = mock(DHPrivateKey.class);
        DHParameterSpec params = mock(DHParameterSpec.class);
        when(dhKey.getParams()).thenReturn(params);
        BigInteger p = mock(BigInteger.class);
        when(p.bitLength()).thenReturn(111);
        when(params.getP()).thenReturn(p);

        int[] chk = new int[1];
        Policy pol = new Policy.Builder("NAME")
                .strengthRule("DH", i -> { chk[0] = (int) i; return true; }, KEYGEN)
                .build();
        pol.checkStrength(KEYGEN, dhKey);
        assertEquals(111, chk[0]);
    }

    @Test(expected = IllegalArgumentException.class)
    public void checkStrengthKeyUnknown() {
        Policy pol = new Policy.Builder("NAME")
                .strengthRule("DH", i -> true, KEYGEN)
                .build();
        Key key = mock(Key.class);
        pol.checkStrength(KEYGEN, key);
    }

    @Test
    public void testNone() throws Exception {

        Policy pol = Fips.none();
        assertEquals("NONE", pol.getPolicyName());

        for (CryptoOp op : CryptoOp.values()) {
            pol.checkStrength(op, "RSA", 1024);
            pol.checkStrength(op, "RSA", 2048);
            pol.checkStrength(op, "RSA", 123);

            pol.checkStrength(op, "EC", 160);
            pol.checkStrength(op, "EC", 224);
            pol.checkStrength(op, "EC", 1);

            pol.checkStrength(op, "DSA", 1024);
            pol.checkStrength(op, "DSA", 1024, 160);
            pol.checkStrength(op, "DSA", 2048);
            pol.checkStrength(op, "DSA", 2048, 224);
            pol.checkStrength(op, "DSA", 512);
            pol.checkStrength(op, "DSA", 512, 160);

            pol.checkStrength(op, "DH", 512);
            pol.checkStrength(op, "DH", 1024);
            pol.checkStrength(op, "DH", 2048);

            pol.checkStrength(op, "HMAC", 1);
            pol.checkStrength(op, "HMAC", 1000);

            pol.checkStrength(op, "KDF", 1);
            pol.checkStrength(op, "KDF", 112);

            pol.checkStrength(op, "AES", 1000);

            pol.checkStrength(op, "DESede", 1000);

            pol.checkAlg(op, "SHA-1");
            pol.checkAlg(op, "SHA-256");
        }
    }

    private void checkKeyType(Policy pol, CryptoOp op, String keyType) {
        pol.checkKeyType(op, keyType);
    }

    private void checkKeyType(Policy pol, CryptoOp[] ops, String keyType) {
        for (CryptoOp op : ops) {
            pol.checkKeyType(op, keyType);
        }
    }

    private void checkKeyTypeFail(Policy pol, CryptoOp[] ops, String keyType) {
        for (CryptoOp op : ops) {
            try {
                pol.checkKeyType(op, keyType);
                fail("expected checkKeyType failure for " + op + "," + keyType);
            } catch (ProviderException e) {
                // expected
            }
        }
    }

    private void checkStrength(Policy pol, CryptoOp[] ops, String alg, int... size) {
        for (CryptoOp op : ops) {
            pol.checkStrength(op, alg, size);
        }
    }

    private void checkStrengthFail(Policy pol, CryptoOp[] ops, String alg, int... size) {
        for (CryptoOp op : ops) {
            try {
                pol.checkStrength(op, alg, size);
                fail("expected checkStrength failure for " + op + "," + alg + ", " + Arrays.toString(size));
            } catch (ProviderException e) {
                // expected
            }
        }
    }

    private void checkAlg(Policy pol, CryptoOp[] ops, String alg) {
        for (CryptoOp op : ops) {
            pol.checkAlg(op, alg);
        }
    }

    private void checkAlgFail(Policy pol, CryptoOp[] ops, String alg) {
        for (CryptoOp op : ops) {
            try {
                pol.checkAlg(op, alg);
                fail("expected checkAlg failure for " + op + "," + alg);
            } catch (ProviderException e) {
                // expected
            }
        }
    }

    private CryptoOp[] ops(CryptoOp... ops) {
        return ops;
    }

    private void checkApproved(Policy pol) {
        for (String keyType : new String[]{"RSA", "EC", "DH"}) {
            checkKeyType(pol, ops(SIGN, VERIFY), keyType);
        }

        checkStrength(pol, ops(KEYGEN, SIGN, VERIFY, ENCRYPT_ASYM, DECRYPT_ASYM), "RSA", 2048);
        checkStrength(pol,  ops(KEYGEN, SIGN, VERIFY, ENCRYPT_ASYM, DECRYPT_ASYM), "RSA", 3072);

        checkStrength(pol, ops(KEYGEN, SIGN, VERIFY, KEYAGREE), "EC", 224);
        checkStrength(pol, ops(KEYGEN, SIGN, VERIFY, KEYAGREE), "EC", 521);

        checkStrength(pol, ops(KEYGEN, KEYAGREE), "DH", 2048);
        checkStrength(pol, ops(KEYGEN, KEYAGREE), "DH", 3072);

        checkStrength(pol, ops(MAC), "HMAC", 112);
        checkStrength(pol, ops(MAC), "HMAC", 1000);

        checkStrength(pol, ops(KEYGEN, KEYDERIVE), "KDF", 112);

        checkStrength(pol, ops(ENCRYPT_SYM, DECRYPT_SYM), "AES", 128);
        checkStrength(pol, ops(ENCRYPT_SYM, DECRYPT_SYM), "AES", 256);

        checkAlg(pol, ops(SIGN, VERIFY), "SHA-224");
        checkAlg(pol, ops(SIGN, VERIFY), "SHA-384");
    }

    private void checkNotAllowed(Policy pol) {
        // DSA keys are not supported in STRICT FIPS enforcement mode
        if (!pol.getPolicyName().equals(Fips.EnforcementPolicy.FIPS_STRICT.name())) {
            checkKeyTypeFail(pol, ops(SIGN), "DSA");
        }

        checkStrengthFail(pol, ops(VERIFY), "RSA", 512);
        checkStrengthFail(pol, ops(KEYGEN, SIGN, ENCRYPT_ASYM, DECRYPT_ASYM), "RSA", 1024);
        checkStrengthFail(pol, ops(KEYGEN, SIGN, ENCRYPT_ASYM, DECRYPT_ASYM), "RSA", 2040);

        checkStrengthFail(pol, ops(VERIFY), "EC", 112);
        checkStrengthFail(pol, ops(KEYGEN, SIGN, KEYAGREE), "EC", 160);
        checkStrengthFail(pol, ops(KEYGEN, SIGN, KEYAGREE), "EC", 223);

        checkStrengthFail(pol, ops(KEYGEN, KEYAGREE), "DH", 1024);
        checkStrengthFail(pol, ops(KEYGEN, KEYAGREE), "DH", 223);

        checkStrengthFail(pol, ops(MAC), "HMAC", -1);

        checkStrengthFail(pol, ops(KEYGEN, KEYDERIVE), "KDF", 111);

        checkStrengthFail(pol, ops(ENCRYPT_SYM, DECRYPT_SYM), "AES", 80);

        // DESede keys are not supported in STRICT FIPS enforcement mode
        if (!pol.getPolicyName().equals(Fips.EnforcementPolicy.FIPS_STRICT.name())) {
            checkStrengthFail(pol, ops(ENCRYPT_SYM, DECRYPT_SYM), "DESede", 112);
        }

        checkAlgFail(pol, ops(SIGN), "SHA-1");
    }

    @Test
    public void testAllowed() throws Exception {
        Policy pol = Fips.fipsPolicy();
        assertEquals("FIPS", pol.getPolicyName());

        checkApproved(pol);
        checkNotAllowed(pol);

        checkStrength(pol, ops(ENCRYPT_SYM, DECRYPT_SYM), "DESede", 192);

        checkKeyType(pol, ops(VERIFY), "DSA");
        checkStrength(pol, ops(VERIFY), "DSA", 2048, 224);
        checkStrength(pol, ops(VERIFY), "DSA", 2048, 256);
        checkStrength(pol, ops(VERIFY), "DSA", 3072, 256);
        checkStrength(pol, ops(VERIFY), "DSA", 2048);
        checkStrength(pol, ops(VERIFY), "DSA", 3072);

        checkStrength(pol, ops(VERIFY), "RSA", 1024);
        checkStrength(pol, ops(VERIFY), "EC", 160);
        checkStrength(pol, ops(VERIFY), "DSA", 1024, 256);
        checkStrength(pol, ops(MAC), "HMAC", 80);

        pol.checkAlg(VERIFY, "SHA-1");
    }

    @Test
    public void testStrict() throws Exception {
        Policy pol = Fips.fipsStrictPolicy();
        assertEquals(Fips.EnforcementPolicy.FIPS_STRICT.name(), pol.getPolicyName());

        checkApproved(pol);
        checkNotAllowed(pol);

        // DesEDE and DSA keys are not supported in FIPS_STRICT mode

        checkStrengthFail(pol, ops(VERIFY), "RSA", 1024);
        checkStrengthFail(pol, ops(VERIFY), "EC", 160);
        checkStrengthFail(pol, ops(MAC), "HMAC", 80);

        checkAlgFail(pol, ops(SIGN, VERIFY), "SHA-1");
    }
}
