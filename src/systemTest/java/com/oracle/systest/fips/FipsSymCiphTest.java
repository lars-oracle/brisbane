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

package com.oracle.systest.fips;

import java.security.InvalidKeyException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.Cipher;
import javax.crypto.SecretKey;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assume;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;

import static com.oracle.jiphertest.util.EnvUtil.FipsPolicy.STRICT;
import static com.oracle.systest.SysTestUtil.isFipsException;
import static com.oracle.systest.fips.OperationResult.FIPS_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.OTHER_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.SUCCESS;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class FipsSymCiphTest {

    private final String alg;
    private final int size;
    private final OperationResult expectedEnc;
    private final OperationResult expectedDec;

    public FipsSymCiphTest(EnvUtil.FipsPolicy policy, String alg, int keySizeBytes, OperationResult encryptExpected, OperationResult decryptExpected) {
        Assume.assumeTrue(isDESEDESupported() || !alg.toUpperCase().startsWith("DESEDE"));
        this.alg = alg;
        this.size = keySizeBytes;
        this.expectedEnc = encryptExpected;
        this.expectedDec = decryptExpected;
    }

    static boolean isDESEDESupported() {
        return (EnvUtil.getPolicy() != STRICT) && FipsProviderInfoUtil.isDESEDESupported();
    }

    static boolean isDESEDEEncryptSupported() {
        return isDESEDESupported() &&
                (FipsProviderInfoUtil.getMajorVersion() == 3 && FipsProviderInfoUtil.getMinorVersion() < 4);
    }

    @Parameterized.Parameters(name="policy={0}:{1}:{2}:encryptExpect={3}:decryptExpect={4}")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> p = new ArrayList<>();
        EnvUtil.FipsPolicy policy = EnvUtil.getPolicy();

        if (policy == EnvUtil.FipsPolicy.NONE) {
            p.add(new Object[]{policy, "AES/CBC/PKCS5Padding", 16, SUCCESS, SUCCESS});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 16, OTHER_EXCEPTION, OTHER_EXCEPTION});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 24,
                    isDESEDEEncryptSupported() ? SUCCESS : OTHER_EXCEPTION, SUCCESS});
        } else if (policy == EnvUtil.FipsPolicy.FIPS) {
            p.add(new Object[]{policy, "AES/CBC/PKCS5Padding", 16, SUCCESS, SUCCESS});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 16, OTHER_EXCEPTION, OTHER_EXCEPTION});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 24, FIPS_EXCEPTION, SUCCESS});
        } else if  (policy == EnvUtil.FipsPolicy.STRICT) {
            p.add(new Object[]{policy, "AES/CBC/PKCS5Padding", 16, SUCCESS, SUCCESS});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 16, OTHER_EXCEPTION, OTHER_EXCEPTION});
            p.add(new Object[]{policy, "DESede/CBC/PKCS5Padding", 24, FIPS_EXCEPTION, FIPS_EXCEPTION});
        }

        return p;
    }

    @Test
    public void encrypt() throws Exception {
        try {
            SecretKey key = new SecretKeySpec(new byte[this.size], this.alg);
            Cipher ciph = ProviderUtil.getCipher(this.alg);
            // Disable delayed provider selection
            assertEquals("JipherJCE", ciph.getProvider().getName());
            ciph.init(Cipher.ENCRYPT_MODE, key);
            assertEquals(this.expectedEnc, SUCCESS);
        } catch (InvalidKeyException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedEnc, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedEnc, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedEnc, OTHER_EXCEPTION);
        }
    }

    @Test
    public void decrypt() throws Exception {
        try {
            SecretKey key = new SecretKeySpec(new byte[this.size], this.alg);
            AlgorithmParameterSpec params = new IvParameterSpec(new byte[this.alg.contains("DESede") ? 8 : 16]);
            Cipher ciph = ProviderUtil.getCipher(this.alg);
            // Disable delayed provider selection
            assertEquals("JipherJCE", ciph.getProvider().getName());
            ciph.init(Cipher.DECRYPT_MODE, key, params);
            assertEquals(this.expectedDec, SUCCESS);
        } catch (InvalidKeyException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedDec, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedDec, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expectedDec, OTHER_EXCEPTION);
        }
    }
}
