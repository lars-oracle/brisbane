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

import java.security.InvalidAlgorithmParameterException;
import java.security.spec.AlgorithmParameterSpec;
import java.util.ArrayList;
import java.util.Collection;
import java.util.List;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;
import javax.crypto.spec.SecretKeySpec;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.Parameterized;

import com.oracle.jiphertest.util.EnvUtil;
import com.oracle.jiphertest.util.FipsProviderInfoUtil;
import com.oracle.jiphertest.util.ProviderUtil;
import com.oracle.jiphertest.util.TlsUtil;

import static com.oracle.systest.SysTestUtil.isFipsException;
import static com.oracle.systest.fips.OperationResult.FIPS_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.OTHER_EXCEPTION;
import static com.oracle.systest.fips.OperationResult.SUCCESS;
import static org.junit.Assert.assertEquals;

@RunWith(Parameterized.class)
public class FipsKeyGenTest {
    static final int MIN_SECURITY_STRENGTH = 112; //bits

    static final SecretKey SHORT_PREMASTER_SECRET  = new SecretKeySpec(new byte[MIN_SECURITY_STRENGTH / 8 - 1], "TlsPremasterSecret");
    static final byte[] EMS_SESSION_HASH = new byte[48];

    private final AlgorithmParameterSpec spec;
    private final OperationResult expected;

    public FipsKeyGenTest(EnvUtil.FipsPolicy policy, String paramLabel, AlgorithmParameterSpec spec, OperationResult expected) {
        this.spec = spec;
        this.expected = expected;
    }

    @Parameterized.Parameters(name="policy={0}:{1}:expect={3}")
    public static Collection<Object[]> params() throws Exception {
        List<Object[]> p = new ArrayList<>();
        EnvUtil.FipsPolicy policy = EnvUtil.getPolicy();
        if (policy == EnvUtil.FipsPolicy.NONE) {
            p.add(new Object[] {policy, "short pre-master secret",
                    TlsUtil.newTlsMasterSecretParameterSpec(SHORT_PREMASTER_SECRET, 3, 3,
                            EMS_SESSION_HASH, "SHA-256", 32, 64),
                    (FipsProviderInfoUtil.getMajorVersion() == 3 && FipsProviderInfoUtil.getMinorVersion() < 4) ?
                        SUCCESS: OTHER_EXCEPTION});
        } else {
            p.add(new Object[] {policy, "short pre-master secret",
                    TlsUtil.newTlsMasterSecretParameterSpec(SHORT_PREMASTER_SECRET, 3, 3,
                            EMS_SESSION_HASH, "SHA-256", 32, 64),
                    FIPS_EXCEPTION});
        }
        return p;
    }

    @Test
    public void generateSecret() throws Exception {
        KeyGenerator kg = ProviderUtil.getKeyGenerator("SunTlsExtendedMasterSecret");
        // Disable delayed provider selection
        Assert.assertEquals("JipherJCE", kg.getProvider().getName());
        try {
            kg.init(this.spec);
            kg.generateKey();
            assertEquals(this.expected, SUCCESS);
        } catch (InvalidAlgorithmParameterException e) {
            if (isFipsException(e)) {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, FIPS_EXCEPTION);
            } else {
                assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
            }
        } catch (Exception e) {
            assertEquals("Unexpected error:(" + e.getMessage() +")", this.expected, OTHER_EXCEPTION);
        }
    }
}
